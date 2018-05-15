package debug

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/dictionary"
)

type Config struct {
	Dictionary *dictionary.Dictionary
}

func DumpString(c *Config, p *radius.Packet) string {
	var b bytes.Buffer
	Dump(&b, c, p)
	b.Truncate(b.Len() - 1) // remove trailing \n
	return b.String()
}

func Dump(w io.Writer, c *Config, p *radius.Packet) {
	io.WriteString(w, p.Code.String())
	io.WriteString(w, " Id ")
	io.WriteString(w, strconv.Itoa(int(p.Identifier)))
	io.WriteString(w, "\n")

	for _, elem := range sortedAttributes(p.Attributes) {
		attrsType, attrs := elem.Type, elem.Attrs
		if len(attrs) == 0 {
			continue
		}

		attrsTypeIntStr := strconv.Itoa(int(attrsType))
		var attrTypeString string
		var stringerFunc func(value []byte) string
		dictAttr := dictionary.AttributeByOID(c.Dictionary.Attributes, attrsTypeIntStr)
		if dictAttr != nil {
			attrTypeString = dictAttr.Name
			switch dictAttr.Type {
			case dictionary.AttributeString, dictionary.AttributeOctets:
				stringerFunc = func(value []byte) string {
					if dictAttr != nil && dictAttr.FlagEncrypt != nil && *dictAttr.FlagEncrypt == 1 {
						decryptedValue, err := radius.UserPassword(radius.Attribute(value), p.Secret, p.Authenticator[:])
						if err != nil {
							return "0x" + hex.EncodeToString(value)
						}
						value = decryptedValue
					}
					return fmt.Sprintf("%q", value)
				}

			case dictionary.AttributeDate:
				stringerFunc = func(value []byte) string {
					if len(value) != 4 {
						return "0x" + hex.EncodeToString(value)
					}
					return time.Unix(int64(binary.BigEndian.Uint32(value)), 0).UTC().Format(time.RFC3339)
				}

			case dictionary.AttributeInteger:
				stringerFunc = func(value []byte) string {
					switch len(value) {
					case 4:
						intVal := int(binary.BigEndian.Uint32(value))
						if dictAttr != nil {
							var matchedNames []string
							for _, value := range dictionary.ValuesByAttribute(c.Dictionary.Values, dictAttr.Name) {
								if value.Number == intVal {
									matchedNames = append(matchedNames, value.Name)
								}
							}
							if len(matchedNames) > 0 {
								sort.Stable(sort.StringSlice(matchedNames))
								return strings.Join(matchedNames, " / ")
							}
						}
						return strconv.Itoa(intVal)
					case 8:
						return strconv.Itoa(int(binary.BigEndian.Uint64(value)))
					}
					return "0x" + hex.EncodeToString(value)
				}

			case dictionary.AttributeIPAddr, dictionary.AttributeIPv6Addr:
				stringerFunc = func(value []byte) string {
					switch len(value) {
					case net.IPv4len, net.IPv6len:
						return net.IP(value).String()
					}
					return "0x" + hex.EncodeToString(value)
				}

			case dictionary.AttributeIFID:
				stringerFunc = func(value []byte) string {
					if len(value) == 8 {
						return net.HardwareAddr(value).String()
					}
					return "0x" + hex.EncodeToString(value)
				}

			default:
				stringerFunc = func(value []byte) string {
					return "0x" + hex.EncodeToString(value)
				}

			}
		} else {
			attrTypeString = "#" + attrsTypeIntStr
			stringerFunc = func(value []byte) string {
				return "0x" + hex.EncodeToString(value)
			}
		}

		for _, attr := range attrs {
			io.WriteString(w, "  ")
			io.WriteString(w, attrTypeString)
			io.WriteString(w, " = ")
			io.WriteString(w, stringerFunc(attr))
			io.WriteString(w, "\n")
		}
	}
}

type attributesElement struct {
	Type  radius.Type
	Attrs []radius.Attribute
}

func sortedAttributes(attributes radius.Attributes) []attributesElement {
	var sortedAttrs []attributesElement
	for attrsType, attrs := range attributes {
		sortedAttrs = append(sortedAttrs, attributesElement{
			Type:  attrsType,
			Attrs: attrs,
		})
	}

	sort.Sort(sortAttributesType(sortedAttrs))

	return sortedAttrs
}

type sortAttributesType []attributesElement

func (s sortAttributesType) Len() int           { return len(s) }
func (s sortAttributesType) Less(i, j int) bool { return s[i].Type < s[j].Type }
func (s sortAttributesType) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
