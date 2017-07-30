package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"unicode"
)

// from golint
var commonInitialisms = map[string]bool{
	"ACL":   true,
	"API":   true,
	"ASCII": true,
	"CPU":   true,
	"CSS":   true,
	"DNS":   true,
	"EOF":   true,
	"GUID":  true,
	"HTML":  true,
	"HTTP":  true,
	"HTTPS": true,
	"ID":    true,
	"IP":    true,
	"JSON":  true,
	"LHS":   true,
	"QPS":   true,
	"RAM":   true,
	"RHS":   true,
	"RPC":   true,
	"SLA":   true,
	"SMTP":  true,
	"SQL":   true,
	"SSH":   true,
	"TCP":   true,
	"TLS":   true,
	"TTL":   true,
	"UDP":   true,
	"UI":    true,
	"UID":   true,
	"UUID":  true,
	"URI":   true,
	"URL":   true,
	"UTF8":  true,
	"VM":    true,
	"XML":   true,
	"XMPP":  true,
	"XSRF":  true,
	"XSS":   true,
}

func nameToIdentifier(name string) string {
	fields := strings.FieldsFunc(name, func(r rune) bool {
		return !unicode.IsNumber(r) && !unicode.IsLetter(r)
	})
	var id bytes.Buffer
	for _, field := range fields {
		fieldUpper := strings.ToUpper(field)
		if commonInitialisms[fieldUpper] {
			id.WriteString(fieldUpper)
		} else {
			id.WriteString(strings.Title(field))
		}
	}
	return id.String()
}

type DictionaryAttributeType int

const (
	DictionaryAttributeString DictionaryAttributeType = iota + 1
	DictionaryAttributeOctets
	DictionaryAttributeIPAddr
	DictionaryAttributeDate
	DictionaryAttributeInteger
	DictionaryAttributeIPv6Addr
	DictionaryAttributeIPv6Prefix
	DictionaryAttributeIFID
	DictionaryAttributeInteger64

	DictionaryAttributeVSA
	// TODO: non-standard types?
)

func (t DictionaryAttributeType) String() string {
	switch t {
	case DictionaryAttributeString:
		return "string"
	case DictionaryAttributeOctets:
		return "octets"
	case DictionaryAttributeIPAddr:
		return "ipaddr"
	case DictionaryAttributeDate:
		return "date"
	case DictionaryAttributeInteger:
		return "integer"
	case DictionaryAttributeIPv6Addr:
		return "ipv6addr"
	case DictionaryAttributeIPv6Prefix:
		return "ipv6prefix"
	case DictionaryAttributeIFID:
		return "ifid"
	case DictionaryAttributeInteger64:
		return "integer64"
	case DictionaryAttributeVSA:
		return "vsa"
	}
	return "DictionaryAttributeType(" + strconv.Itoa(int(t)) + ")"
}

type DictionaryValue struct {
	Attribute string
	Name      string
	Number    int

	Identifier string
}

func ParseDictionaryValue(f []string) (*DictionaryValue, error) {
	value := &DictionaryValue{
		Attribute: f[1],
		Name:      f[2],
	}

	value.Identifier = nameToIdentifier(value.Name)
	if value.Identifier == "" {
		return nil, errors.New("invalid name " + value.Name)
	}

	number64, err := strconv.ParseInt(f[3], 10, 32)
	if err != nil {
		return nil, err
	}
	value.Number = int(number64)

	return value, err
}

type DictionaryAttribute struct {
	Name    string
	OID     int
	Type    DictionaryAttributeType
	Encrypt int
	HasTag  bool

	Identifier string
	Values     map[string]*DictionaryValue
}

func (a *DictionaryAttribute) SortedValues() []*DictionaryValue {
	values := make([]*DictionaryValue, 0, len(a.Values))
	for _, value := range a.Values {
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].Number < values[j].Number
	})
	return values
}

func ParseDictionaryAttribute(f []string) (*DictionaryAttribute, error) {
	attr := &DictionaryAttribute{
		Name: f[1],

		Values: make(map[string]*DictionaryValue),
	}

	attr.Identifier = nameToIdentifier(f[1])
	if attr.Identifier == "" {
		return nil, errors.New("invalid name " + f[1])
	}

	oid, err := strconv.ParseInt(f[2], 10, 32)
	if err != nil {
		return nil, errors.New("invalid oid " + f[2])
	}
	attr.OID = int(oid)

	switch f[3] {
	case "string":
		attr.Type = DictionaryAttributeString
	case "octets":
		attr.Type = DictionaryAttributeOctets
	case "ipaddr":
		attr.Type = DictionaryAttributeIPAddr
	case "date":
		attr.Type = DictionaryAttributeDate
	case "integer":
		attr.Type = DictionaryAttributeInteger
	case "ipv6addr":
		attr.Type = DictionaryAttributeIPv6Addr
	case "ipv6prefix":
		attr.Type = DictionaryAttributeIPv6Prefix
	case "ifid":
		attr.Type = DictionaryAttributeIFID
	case "integer64":
		attr.Type = DictionaryAttributeInteger64
	case "vsa":
		attr.Type = DictionaryAttributeVSA
	default:
		return nil, errors.New("unknown type " + f[3])
	}

	if len(f) >= 5 {
		flags := strings.Split(f[4], ",")
		var (
			seenEncrypt bool
			seenHasTag  bool
		)
		for _, f := range flags {
			switch f {
			case "encrypt=1":
				if seenEncrypt {
					return nil, errors.New("duplicate encrypt flag")
				}
				attr.Encrypt = 1
				seenEncrypt = true
			case "encrypt=2":
				if seenEncrypt {
					return nil, errors.New("duplicate encrypt flag")
				}
				attr.Encrypt = 2
				seenEncrypt = true
			case "encrypt=3":
				if seenEncrypt {
					return nil, errors.New("duplicate encrypt flag")
				}
				attr.Encrypt = 3
				seenEncrypt = true
			case "has_tag":
				if seenHasTag {
					return nil, errors.New("duplicate has_tag flag")
				}
				attr.HasTag = true
				seenHasTag = true
			default:
				return nil, errors.New("unknown flag " + f)
			}
		}
	}

	return attr, nil
}

type DictionaryVendor struct {
	Name         string
	Number       int
	TypeOctets   int
	LengthOctets int
}

type Dictionary struct {
	Attributes map[string]*DictionaryAttribute
	Vendors    map[string]*DictionaryVendor
}

func (d *Dictionary) SortedAttributes() []*DictionaryAttribute {
	attrs := make([]*DictionaryAttribute, 0, len(d.Attributes))
	for _, attr := range d.Attributes {
		attrs = append(attrs, attr)
	}
	sort.Slice(attrs, func(i, j int) bool {
		return attrs[i].OID < attrs[j].OID
	})
	return attrs
}

func main() {
	packageName := flag.String("package", "main", "generated package name")
	outputFile := flag.String("output", "-", "output file (\"-\" writes to standard out)")
	flag.Parse()

	dict := &Dictionary{
		Attributes: make(map[string]*DictionaryAttribute),
		Vendors:    make(map[string]*DictionaryVendor),
	}

	for _, filename := range flag.Args() {
		// TODO: recursive check

		func() {
			f, err := os.Open(filename)
			if err != nil {
				fmt.Printf("radius-dict-gen: %s\n", err)
				os.Exit(1)
			}
			defer f.Close()

			s := bufio.NewScanner(f)

			for i := 1; s.Scan(); i++ {
				line := s.Text()
				if idx := strings.IndexByte(line, '#'); idx >= 0 {
					line = line[:idx]
				}
				if len(line) == 0 {
					continue
				}

				fields := strings.Fields(line)
				switch {
				case (len(fields) == 4 || len(fields) == 5) && fields[0] == "ATTRIBUTE":
					attr, err := ParseDictionaryAttribute(fields)
					if err != nil {
						fmt.Printf("radius-dict-gen: invalid attribute in %s:%d: %s\n", filename, i, err)
						os.Exit(1)
					}
					if _, existing := dict.Attributes[attr.Name]; existing {
						fmt.Printf("radius-dict-gen: duplicate attribute %s defined at %s:%d\n", attr.Name, filename, i)
						os.Exit(1)
					}
					// TODO: vendor?
					dict.Attributes[attr.Name] = attr

				case len(fields) == 4 && fields[0] == "VALUE":

					value, err := ParseDictionaryValue(fields)
					if err != nil {
						fmt.Printf("radius-dict-gen: invalid value in %s:%d: %s\n", filename, i, err)
						os.Exit(1)
					}

					attr := dict.Attributes[value.Attribute]
					if attr == nil {
						fmt.Printf("radius-dict-gen: unknown attribute %s referenced at %s:%d\n", value.Attribute, filename, i)
						os.Exit(1)
					}

					if _, valueExists := attr.Values[value.Name]; valueExists {
						fmt.Printf("radius-dict-gen: duplicate attribute %s value %s referenced at %s:%d\n", value.Attribute, value.Name, filename, i)
						os.Exit(1)
					}

					for _, v := range attr.Values {
						if v.Number == value.Number {
							// FreeRADIUS has duplicate values
							fmt.Fprintf(os.Stderr, "radius-dict-gen: duplicate attribute value %d as %s (previously defined as %s); overwriting\n", value.Number, value.Name, v.Name)
							delete(attr.Values, v.Name)
							break
						}
					}

					// TODO: vendor?
					attr.Values[value.Name] = value

				//case (len(fields) == 3 && len(fields) == 4) && fields[0] == "VENDOR":
				//case len(fields) == 2 && fields[0] == "BEGIN-VENDOR":
				//case len(fields) == 2 && fields[0] == "END-VENDOR":
				//case len(fields) == 2 && fields[0] == "$INCLUDE":
				default:
					fmt.Printf("radius-dict-gen: invalid line in %s:%d\n", filename, i)
					os.Exit(1)
				}
			}

			if err := s.Err(); err != nil {
				fmt.Printf("radius-dict-gen: %s\n", err)
				os.Exit(1)
			}
		}()
	}

	var output io.WriteCloser
	if *outputFile == "-" {
		output = os.Stdout
	} else {
		outFile, err := os.Create(*outputFile)
		if err != nil {
			fmt.Printf("radius-dict-gen: %s\n", err)
			os.Exit(1)
		}
		output = outFile
	}

	data := struct {
		Package string
		Dict    *Dictionary
	}{
		Package: *packageName,
		Dict:    dict,
	}

	var b bytes.Buffer
	if err := tpl.Execute(&b, &data); err != nil {
		fmt.Printf("radius-dict-gen: %s\n", err)
		os.Exit(1)
	}

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		output.Write(b.Bytes())
		fmt.Printf("radius-dict-gen: %s\n", err)
		os.Exit(1)
	}

	output.Write(formatted)

	if err := output.Close(); err != nil {
		fmt.Printf("radius-dict-gen: %s\n", err)
		os.Exit(1)
	}
}

var tpl = template.Must(template.New("gen").Parse(`// Generated by radius-dict-gen. DO NOT EDIT.

package {{ .Package }}

import (
	"net"
	"strconv"

	"layeh.com/radius"
)

var _ = radius.Type(0)
var _ = strconv.Itoa
var _ = net.ParseIP

{{ with .Dict.SortedAttributes }}
const ({{ range . }}
	{{ .Identifier}}_Type radius.Type = {{ .OID }}{{ end }}
)
{{ end }}

{{ with .Dict.SortedAttributes }}
{{ range . }}
{{ $attr := . }}
{{ if eq .Type.String "integer" }}
type {{ .Identifier }} uint32

{{ if gt (len .Values) 0 }}
const ({{ range .SortedValues }}
	{{ $attr.Identifier }}_Value_{{ .Identifier}} {{ $attr.Identifier }} = {{ .Number }}{{ end }}
)
{{ end }}

var {{ .Identifier}}_Strings = map[{{ .Identifier}}]string{{ "{" }}{{ range .SortedValues }}
	{{ $attr.Identifier }}_Value_{{ .Identifier}}: "{{ .Name }}",{{ end }}
}

func (a {{ .Identifier }}) String() string {
	if str, ok := {{ .Identifier}}_Strings[a]; ok {
		return str
	}
	return "{{ .Identifier }}(" + strconv.Itoa(int(a)) + ")"
}

func {{ .Identifier }}_Add(p *radius.Packet, value {{ .Identifier }}) {
	a := radius.NewInteger(uint32(value))
	p.Add({{ .Identifier }}_Type, a)
}

func {{ .Identifier }}_Get(p *radius.Packet) (value {{ .Identifier }}) {
	value, _ = {{ .Identifier }}_Lookup(p)
	return
}

func {{ .Identifier }}_Gets(p *radius.Packet) (values []{{ .Identifier }}, err error) {
	var i uint32
	for _, attr := range p.Attributes[{{ .Identifier }}_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, {{ .Identifier }}(i))
	}
	return
}

func {{ .Identifier }}_Lookup(p *radius.Packet) (value {{ .Identifier }}, err error) {
	a, ok  := p.Lookup({{ .Identifier }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = {{ .Identifier}}(i)
	return
}

func {{ .Identifier }}_Set(p *radius.Packet, value {{ .Identifier }}) {
	a := radius.NewInteger(uint32(value))
	p.Set({{ .Identifier }}_Type, a)
}

{{ else if or (eq .Type.String "string") (eq .Type.String "octets") }}

func {{ .Identifier }}_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	{{ if eq .Encrypt 1 }}
	a, err = radius.NewUserPassword(value, p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewBytes(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Add({{ .Identifier }}_Type, a)
	return nil
}

func {{ .Identifier }}_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	{{ if eq .Encrypt 1 }}
	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewString(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Add({{ .Identifier }}_Type, a)
	return nil
}

func {{ .Identifier }}_Get(p *radius.Packet) (value []byte) {
	value, _ = {{ .Identifier }}_Lookup(p)
	return
}

func {{ .Identifier }}_GetString(p *radius.Packet) (value string) {
	return string({{ .Identifier }}_Get(p))
}

func {{ .Identifier }}_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[{{ .Identifier }}_Type] {
		{{ if eq .Encrypt 1 }}
		i, err = radius.UserPassword(attr, p.Secret, p.Authenticator[:])
		{{ else }}
		i = radius.Bytes(attr)
		{{ end }}
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func {{ .Identifier }}_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[{{ .Identifier }}_Type] {
		{{ if eq .Encrypt 1 }}
		var up radius.Attribute
		up, err = radius.UserPassword(attr, p.Secret, p.Authenticator[:])
		if err == nil {
			i = string(up)
		}
		{{ else }}
		i = radius.String(attr)
		{{ end }}
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func {{ .Identifier }}_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok  := p.Lookup({{ .Identifier }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	{{ if eq .Encrypt 1 }}
	value, err = radius.UserPassword(a, p.Secret, p.Authenticator[:])
	{{ else }}
	value = radius.Bytes(a)
	{{ end }}
	return
}

func {{ .Identifier }}_LookupString(p *radius.Packet) (value string, err error) {
	a, ok  := p.Lookup({{ .Identifier }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	{{ if eq .Encrypt 1 }}
	var b []byte
	b, err = radius.UserPassword(a, p.Secret, p.Authenticator[:])
	if err == nil {
		value = string(b)
	}
	{{ else }}
	value = radius.String(a)
	{{ end }}
	return
}

func {{ .Identifier }}_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	{{ if eq .Encrypt 1 }}
	a, err = radius.NewUserPassword(value, p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewBytes(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Set({{ .Identifier }}_Type, a)
	return
}

func {{ .Identifier }}_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	{{ if eq .Encrypt 1 }}
	a, err = radius.NewUserPassword([]byte(value), p.Secret, p.Authenticator[:])
	{{ else }}
	a, err = radius.NewString(value)
	{{ end }}
	if err != nil {
		return
	}
	p.Set({{ .Identifier }}_Type, a)
	return
}

{{ else if eq .Type.String "ipaddr" }}

func {{ .Identifier }}_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add({{ .Identifier }}_Type, a)
	return nil
}

func {{ .Identifier }}_Get(p *radius.Packet) (value net.IP) {
	value, _ = {{ .Identifier }}_Lookup(p)
	return
}

func {{ .Identifier }}_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[{{ .Identifier }}_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func {{ .Identifier }}_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok  := p.Lookup({{ .Identifier }}_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func {{ .Identifier }}_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set({{ .Identifier }}_Type, a)
	return
}

{{ else if eq .Type.String "vsa" }}

{{ else }}
// TODO: unimplemented {{ .Name }} (type {{ .Type.String }})
{{ end }}
{{ end }}
{{ end }}
`))
