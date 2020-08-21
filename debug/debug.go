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

func Dump(w io.Writer, c *Config, p *radius.Packet) {
	io.WriteString(w, p.Code.String())
	io.WriteString(w, " Id ")
	io.WriteString(w, strconv.Itoa(int(p.Identifier)))
	io.WriteString(w, "\n")
	dumpAttrs(w, c, p)
}

func DumpString(c *Config, p *radius.Packet) string {
	var b bytes.Buffer
	Dump(&b, c, p)
	b.Truncate(b.Len() - 1) // remove trailing \n
	return b.String()
}

func DumpRequest(w io.Writer, c *Config, req *radius.Request) {
	io.WriteString(w, req.Code.String())
	io.WriteString(w, " Id ")
	io.WriteString(w, strconv.Itoa(int(req.Identifier)))
	io.WriteString(w, " from ")
	io.WriteString(w, req.RemoteAddr.String())
	io.WriteString(w, " to ")
	io.WriteString(w, req.LocalAddr.String())
	io.WriteString(w, "\n")
	dumpAttrs(w, c, req.Packet)
}

func DumpRequestString(c *Config, req *radius.Request) string {
	var b bytes.Buffer
	DumpRequest(&b, c, req)
	b.Truncate(b.Len() - 1) // remove trailing \n
	return b.String()
}

func dumpAttrs(w io.Writer, c *Config, p *radius.Packet) {
	for _, avp := range p.Attributes {
		var attrTypeStr string
		var attrStr string

		searchAttrs := c.Dictionary.Attributes
		searchValues := c.Dictionary.Values

		dictAttr := dictionary.AttributeByOID(searchAttrs, dictionary.OID{int(avp.Type)})
		if dictAttr != nil {
			attrTypeStr = dictAttr.Name
			switch dictAttr.Type {
			case dictionary.AttributeString, dictionary.AttributeOctets:
				if dictAttr != nil && dictAttr.FlagEncrypt.Valid && dictAttr.FlagEncrypt.Int == 1 {
					decryptedValue, err := radius.UserPassword(avp.Attribute, p.Secret, p.CryptoAuthenticator[:])
					if err == nil {
						attrStr = fmt.Sprintf("%q", decryptedValue)
						break
					}
				}
				attrStr = fmt.Sprintf("%q", avp.Attribute)

			case dictionary.AttributeDate:
				if len(avp.Attribute) == 4 {
					t := time.Unix(int64(binary.BigEndian.Uint32(avp.Attribute)), 0).UTC()
					attrStr = t.Format(time.RFC3339)
				}

			case dictionary.AttributeInteger:
				switch len(avp.Attribute) {
				case 4:
					intVal := uint64(binary.BigEndian.Uint32(avp.Attribute))
					if dictAttr != nil {
						var matchedNames []string
						for _, value := range dictionary.ValuesByAttribute(searchValues, dictAttr.Name) {
							if value.Number == intVal {
								matchedNames = append(matchedNames, value.Name)
							}
						}
						if len(matchedNames) > 0 {
							sort.Stable(sort.StringSlice(matchedNames))
							attrStr = strings.Join(matchedNames, " / ")
							break
						}
					}
					attrStr = strconv.FormatUint(intVal, 10)
				case 8:
					attrStr = strconv.Itoa(int(binary.BigEndian.Uint64(avp.Attribute)))
				}

			case dictionary.AttributeIPAddr, dictionary.AttributeIPv6Addr:
				switch len(avp.Attribute) {
				case net.IPv4len, net.IPv6len:
					attrStr = net.IP(avp.Attribute).String()
				}

			case dictionary.AttributeIFID:
				if len(avp.Attribute) == 8 {
					attrStr = net.HardwareAddr(avp.Attribute).String()
				}

			}
		} else {
			attrTypeStr = "#" + strconv.Itoa(int(avp.Type))
		}

		if len(attrStr) == 0 {
			attrStr = "0x" + hex.EncodeToString(avp.Attribute)
		}

		io.WriteString(w, "  ")
		io.WriteString(w, attrTypeStr)
		io.WriteString(w, " = ")
		io.WriteString(w, attrStr)
		io.WriteString(w, "\n")
	}
}
