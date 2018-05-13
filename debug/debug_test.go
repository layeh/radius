package debug_test

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/debug"
	. "layeh.com/radius/rfc2865"
	. "layeh.com/radius/rfc2866"
	. "layeh.com/radius/rfc2869"
)

var secret = []byte(`1234567`)

func TestDumpPacket(t *testing.T) {
	tests := []*struct {
		Packet func() *radius.Packet
		Output []string
	}{
		{
			func() *radius.Packet {
				p := &radius.Packet{
					Code:       radius.CodeAccessRequest,
					Identifier: 33,
					Secret:     secret,
					Attributes: make(radius.Attributes),
				}
				p.Authenticator[0] = 0x01

				UserName_SetString(p, "Tim")
				UserPassword_SetString(p, "12345")
				NASIPAddress_Set(p, net.IPv4(10, 0, 2, 5))
				AcctStatusType_Add(p, 3) // Alive, exists in dictionary file
				AcctStatusType_Add(p, AcctStatusType_Value_InterimUpdate)
				AcctLinkCount_Set(p, 2)
				EventTimestamp_Set(p, time.Date(2018, 5, 13, 11, 55, 10, 0, time.UTC))
				return p
			},
			[]string{
				`Access-Request Id 33`,
				`  User-Name = "Tim"`,
				`  User-Password = "12345"`,
				`  NAS-IP-Address = 10.0.2.5`,
				`  Acct-Status-Type = Alive / Interim-Update`,
				`  Acct-Status-Type = Alive / Interim-Update`,
				`  Acct-Link-Count = 2`,
				`  Event-Timestamp = 2018-05-13T11:55:10Z`,
			},
		},
	}

	config := &debug.Config{
		Dictionary: debug.IncludedDictionary,
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			p := tt.Packet()
			result := debug.DumpString(config, p)
			outputStr := strings.Join(tt.Output, "\n")
			if result != outputStr {
				t.Fatalf("\nexpected:\n%s\ngot:\n%s", outputStr, result)
			}
		})
	}
}
