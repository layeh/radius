package debug

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"

	"layeh.com/radius"
	"layeh.com/radius/dictionary"
)

type Config struct {
	Dictionary *dictionary.Dictionary
}

func DumpPacket(c *Config, p *radius.Packet) string {
	var b bytes.Buffer
	b.WriteString(p.Code.String())
	b.WriteString(" Id ")
	b.WriteString(strconv.Itoa(int(p.Identifier)))
	b.WriteByte('\n')

	for _, elem := range sortedAttributes(p.Attributes) {
		attrsType, attrs := elem.Type, elem.Attrs
		if len(attrs) == 0 {
			continue
		}

		attrsTypeIntStr := strconv.Itoa(int(attrsType))
		var attrTypeString string
		var stringerFunc func(value []byte) string
		dictAttr := c.Dictionary.AttributeByOID(attrsTypeIntStr)
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

			case dictionary.AttributeInteger:
				stringerFunc = func(value []byte) string {
					switch len(value) {
					case 4:
						return strconv.Itoa(int(binary.BigEndian.Uint32(value)))
					case 8:
						return strconv.Itoa(int(binary.BigEndian.Uint64(value)))
					}
					return "0x" + hex.EncodeToString(value)
				}

			case dictionary.AttributeIPAddr:
				stringerFunc = func(value []byte) string {
					return net.IP(value).String()
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
			b.WriteString("  ")
			b.WriteString(attrTypeString)
			b.WriteString(" = ")
			b.WriteString(stringerFunc(attr))
			b.WriteByte('\n')
		}
	}

	b.Truncate(b.Len() - 1) // remove trailing \n

	return b.String()
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
