package debug_test

import (
	"strconv"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/debug"
	. "layeh.com/radius/rfc2865"
)

var secret = []byte(`1234567`)

func TestDumpPacket(t *testing.T) {
	tests := []*struct {
		Packet func() *radius.Packet
		Output string
	}{
		{
			func() *radius.Packet {
				p := radius.New(radius.CodeAccessRequest, secret)
				p.Identifier = 33
				UserName_SetString(p, "Tim")
				UserPassword_SetString(p, "12345")
				return p
			},
			`Access-Request Id 33
  User-Name = "Tim"
  User-Password = "12345"
`,
		},
	}

	config := &debug.Config{
		Dictionary: debug.IncludedDictionary,
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			p := tt.Packet()
			result := debug.DumpPacket(config, p)
			if result != tt.Output {
				t.Fatalf("\nexpected:\n%s\ngot:\n%s", tt.Output, result)
			}
		})
	}
}
