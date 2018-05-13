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
				p := radius.New(radius.CodeAccessRequest, secret)
				p.Identifier = 33
				UserName_SetString(p, "Tim")
				UserPassword_SetString(p, "12345")
				NASIPAddress_Set(p, net.IPv4(10, 0, 2, 5))
				EventTimestamp_Set(p, time.Date(2018, 5, 13, 11, 55, 10, 0, time.UTC))
				return p
			},
			[]string{
				`Access-Request Id 33`,
				`  User-Name = "Tim"`,
				`  User-Password = "12345"`,
				`  NAS-IP-Address = 10.0.2.5`,
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
