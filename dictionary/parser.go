package dictionary

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type File interface {
	io.Reader
	io.Closer
	Name() string
}

type Opener interface {
	OpenFile(name string) (File, error)
}

type FileSystemOpener struct {
	Root string
}

func (f *FileSystemOpener) OpenFile(name string) (File, error) {
	if !filepath.IsAbs(name) {
		name = filepath.Join(f.Root, name)
	}
	absPath, err := filepath.Abs(name)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(absPath)
	return file, err
}

type Parser struct {
	Opener Opener

	// IgnoreIdenticalAttributes specifies whether identical attributes are
	// ignored, rather than a parse error being emitted.
	IgnoreIdenticalAttributes  bool
	IgnoreUnknownAttributeType bool
}

func (p *Parser) Parse(f File) (*Dictionary, error) {
	parsedFiles := map[string]struct{}{
		f.Name(): {},
	}
	dict := new(Dictionary)
	if err := p.parse(dict, parsedFiles, f); err != nil {
		return nil, err
	}
	return dict, nil
}

func (p *Parser) parse(dict *Dictionary, parsedFiles map[string]struct{}, f File) error {
	s := bufio.NewScanner(f)

	var vendorBlock *Vendor

	lineNo := 1
	for ; s.Scan(); lineNo++ {
		line := s.Text()
		line = strings.TrimLeft(line, " ")
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		if len(line) == 0 {
			continue
		}

		fields := strings.Fields(line)
		switch {
		case (len(fields) == 4 || len(fields) == 5) && fields[0] == "ATTRIBUTE":
			attr, err := p.parseAttribute(fields)
			if err != nil {
				switch err.(type) {
				case *UnknownAttributeTypeError:
					if p.IgnoreUnknownAttributeType {
						continue
					}
				}
				return &ParseError{
					Inner: err,
					File:  f,
					Line:  lineNo,
				}
			}

			var existing *Attribute
			if vendorBlock == nil {
				existing = AttributeByName(dict.Attributes, attr.Name)
			} else {
				existing = AttributeByName(vendorBlock.Attributes, attr.Name)
			}
			if existing != nil {
				if p.IgnoreIdenticalAttributes && attr.MostlyEquals(existing) {
					break
				}
				return &ParseError{
					Inner: &DuplicateAttributeError{
						Attribute: attr,
					},
					File: f,
					Line: lineNo,
				}
			}

			if vendorBlock == nil {
				dict.Attributes = append(dict.Attributes, attr)
			} else {
				vendorBlock.Attributes = append(vendorBlock.Attributes, attr)
			}

		case len(fields) == 4 && fields[0] == "VALUE":
			value, err := p.parseValue(fields)
			if err != nil {
				return &ParseError{
					Inner: err,
					File:  f,
					Line:  lineNo,
				}
			}

			// no duplicate check; VALUEs can be overwritten

			if vendorBlock == nil {
				dict.Values = append(dict.Values, value)
			} else {
				vendorBlock.Values = append(vendorBlock.Values, value)
			}

		case (len(fields) == 3 || len(fields) == 4) && fields[0] == "VENDOR":
			vendor, err := p.parseVendor(fields)
			if err != nil {
				return &ParseError{
					Inner: err,
					File:  f,
					Line:  lineNo,
				}
			}

			if existing := vendorByNameOrNumber(dict.Vendors, vendor.Name, vendor.Number); existing == nil || !vendor.Equals(existing) {
				dict.Vendors = append(dict.Vendors, vendor)
			}

		case len(fields) == 2 && fields[0] == "BEGIN-VENDOR":
			// TODO: support RFC 6929 extended VSA?

			if vendorBlock != nil {
				return &ParseError{
					Inner: &NestedVendorBlockError{},
					File:  f,
					Line:  lineNo,
				}
			}

			vendor := VendorByName(dict.Vendors, fields[1])
			if vendor == nil {
				return &ParseError{
					Inner: &UnknownVendorError{
						Vendor: fields[1],
					},
					File: f,
					Line: lineNo,
				}
			}

			vendorBlock = vendor

		case len(fields) == 2 && fields[0] == "END-VENDOR":
			if vendorBlock == nil {
				return &ParseError{
					Inner: &UnmatchedEndVendorError{},
					File:  f,
					Line:  lineNo,
				}
			}
			if vendorBlock.Name != fields[1] {
				return &ParseError{
					Inner: &InvalidEndVendorError{
						Vendor: fields[1],
					},
					File: f,
					Line: lineNo,
				}
			}

			vendorBlock = nil

		case len(fields) == 2 && fields[0] == "$INCLUDE":
			if vendorBlock != nil {
				return &ParseError{
					Inner: &BeginVendorIncludeError{},
					File:  f,
					Line:  lineNo,
				}
			}

			err := func() error {
				incFile, err := p.Opener.OpenFile(fields[1])
				if err != nil {
					return &ParseError{
						Inner: err,
						File:  f,
						Line:  lineNo,
					}
				}
				defer incFile.Close()

				incFileName := incFile.Name()
				if _, included := parsedFiles[incFileName]; included {
					return &ParseError{
						Inner: &RecursiveIncludeError{
							Filename: incFileName,
						},
						File: f,
						Line: lineNo,
					}
				}

				if err := p.parse(dict, parsedFiles, incFile); err != nil {
					return err
				}

				if err := incFile.Close(); err != nil {
					return &ParseError{
						Inner: err,
						File:  f,
						Line:  lineNo,
					}
				}

				return nil
			}()
			if err != nil {
				return err
			}

		default:
			return &ParseError{
				Inner: &UnknownLineError{
					Line: s.Text(),
				},
				File: f,
				Line: lineNo,
			}
		}
	}

	if err := s.Err(); err != nil {
		return err
	}

	if vendorBlock != nil {
		return &ParseError{
			Inner: &UnclosedVendorBlockError{},
			File:  f,
			Line:  lineNo - 1,
		}
	}

	return nil
}

func (p *Parser) ParseFile(filename string) (*Dictionary, error) {
	f, err := p.Opener.OpenFile(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return p.Parse(f)
}

func parseOID(s string) OID {
	var o OID
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		num, err := strconv.ParseInt(s[2:], 16, 32)
		if err != nil {
			return nil
		}

		o = append(o, int(num))
		return o
	}

	for i, ch := range s {
		switch ch {
		case '.':
			if i == 0 || len(s) == i+1 || s[i+1] < '0' || s[i+1] > '9' {
				return nil
			}
			o = append(o, 0)
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			if i == 0 {
				o = append(o, 0)
			}
			o[len(o)-1] *= 10
			o[len(o)-1] += int(ch - '0')
		default:
			return nil
		}
	}
	return o
}

func (p *Parser) parseAttribute(f []string) (*Attribute, error) {
	// 4 <= len(f) <= 5

	oid := parseOID(f[2])
	if len(oid) == 0 {
		return nil, &InvalidOIDError{
			OID: f[2],
		}
	}

	attr := &Attribute{
		Name: f[1],
		OID:  oid,
	}

	switch {
	case strings.EqualFold(f[3], "string"):
		attr.Type = AttributeString
	case strings.EqualFold(f[3], "octets"):
		attr.Type = AttributeOctets
	case len(f[3]) > 8 && strings.EqualFold(f[3][:7], "octets[") && f[3][len(f[3])-1] == ']':
		size, err := strconv.ParseInt(f[3][7:len(f[3])-1], 10, 32)
		if err != nil {
			return nil, &UnknownAttributeTypeError{
				Type: f[3],
			}
		}
		attr.Size = IntFlag{
			Valid: true,
			Int:   int(size),
		}
		attr.Type = AttributeOctets
	case strings.EqualFold(f[3], "ipaddr"):
		attr.Type = AttributeIPAddr
	case strings.EqualFold(f[3], "date"):
		attr.Type = AttributeDate
	case strings.EqualFold(f[3], "integer"):
		attr.Type = AttributeInteger
	case strings.EqualFold(f[3], "ipv6addr"):
		attr.Type = AttributeIPv6Addr
	case strings.EqualFold(f[3], "ipv6prefix"):
		attr.Type = AttributeIPv6Prefix
	case strings.EqualFold(f[3], "ifid"):
		attr.Type = AttributeIFID
	case strings.EqualFold(f[3], "integer64"):
		attr.Type = AttributeInteger64
	case strings.EqualFold(f[3], "vsa"):
		attr.Type = AttributeVSA
	case strings.EqualFold(f[3], "ether"):
		attr.Type = AttributeEther
	case strings.EqualFold(f[3], "abinary"):
		attr.Type = AttributeABinary
	case strings.EqualFold(f[3], "byte"):
		attr.Type = AttributeByte
	case strings.EqualFold(f[3], "short"):
		attr.Type = AttributeShort
	case strings.EqualFold(f[3], "signed"):
		attr.Type = AttributeSigned
	case strings.EqualFold(f[3], "tlv"):
		attr.Type = AttributeTLV
	case strings.EqualFold(f[3], "ipv4prefix"):
		attr.Type = AttributeIPv4Prefix
	default:
		return nil, &UnknownAttributeTypeError{
			Type: f[3],
		}
	}

	if len(f) >= 5 {
		flags := strings.Split(f[4], ",")
		for _, f := range flags {
			switch {
			case strings.HasPrefix(f, "encrypt="):
				if attr.FlagEncrypt.Valid {
					return nil, &DuplicateAttributeFlagError{
						Flag: f,
					}
				}
				encryptTypeStr := strings.TrimPrefix(f, "encrypt=")
				encryptType, err := strconv.ParseInt(encryptTypeStr, 10, 32)
				if err != nil {
					return nil, &InvalidAttributeEncryptTypeError{
						Type: encryptTypeStr,
					}
				}
				attr.FlagEncrypt = IntFlag{
					Valid: true,
					Int:   int(encryptType),
				}
			case f == "has_tag":
				if attr.FlagHasTag.Valid {
					return nil, &DuplicateAttributeFlagError{
						Flag: f,
					}
				}
				attr.FlagHasTag = BoolFlag{
					Valid: true,
					Bool:  true,
				}
			case f == "concat":
				if attr.FlagConcat.Valid {
					return nil, &DuplicateAttributeFlagError{
						Flag: f,
					}
				}
				attr.FlagConcat = BoolFlag{
					Valid: true,
					Bool:  true,
				}
			case f == "virtual":
				continue
			default:
				return nil, &UnknownAttributeFlagError{
					Flag: f,
				}
			}
		}
	}

	return attr, nil
}

func (p *Parser) parseValue(f []string) (*Value, error) {
	// len(f) == 4

	value := &Value{
		Attribute: f[1],
		Name:      f[2],
	}

	numStr := f[3]
	base := 10
	if len(numStr) > 2 && (numStr[0] == '0' && (numStr[1] == 'x' || numStr[1] == 'X')) {
		base = 16
		numStr = numStr[2:]
	}

	number, err := strconv.ParseUint(numStr, base, 32)
	if err != nil {
		return nil, err
	}
	value.Number = uint(number)

	return value, nil
}

func (p *Parser) parseVendor(f []string) (*Vendor, error) {
	// 3 <= len(f) <= 4

	number, err := strconv.ParseInt(f[2], 10, 32)
	if err != nil {
		return nil, err
	}

	vendor := &Vendor{
		Name:   f[1],
		Number: int(number),
	}

	if len(f) == 4 {
		// "format=t,l"
		// t ∈ [1, 2, 4]
		// l ∈ [0, 1, 2]
		if !strings.HasPrefix(f[3], "format=") || len(f[3]) < 10 || f[3][8] != ',' || (f[3][7] != '1' && f[3][7] != '2' && f[3][7] != '4') || (f[3][9] < '0' || f[3][9] > '2') {
			return nil, &InvalidVendorFormatError{
				Format: f[3],
			}
		}
		vendor.TypeOctets = new(int)
		*vendor.TypeOctets = int(f[3][7] - '0')
		vendor.LengthOctets = new(int)
		*vendor.LengthOctets = int(f[3][9] - '0')
	}

	return vendor, nil
}
