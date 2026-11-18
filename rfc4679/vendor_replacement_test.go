package rfc4679

import (
	"bytes"
	"fmt"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"testing"
)

func TestOversizedVendorReplacementPreservesPacket(t *testing.T) {
	for length := 248; length <= 254; length++ {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			p := radius.New(radius.CodeAccessRequest, []byte("secret"))
			if err := rfc2865.UserName_SetString(p, "user"); err != nil {
				t.Fatal(err)
			}
			// The old value shares a VSA with an unrelated nested attribute.
			vsa, err := radius.NewVendorSpecific(_ADSLForum_VendorID, radius.Attribute{1, 5, 'o', 'l', 'd', 2, 6, 'k', 'e', 'e', 'p'})
			if err != nil {
				t.Fatal(err)
			}
			p.Add(rfc2865.VendorSpecific_Type, vsa)
			before, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if err := ADSLAgentCircuitID_Set(p, bytes.Repeat([]byte{'x'}, length)); err == nil {
				t.Fatal("oversized replacement succeeded")
			}
			after, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("failed replacement changed packet: before %x, after %x", before, after)
			}
			parsed, err := radius.Parse(after, p.Secret)
			if err != nil {
				t.Fatal(err)
			}
			if value, err := ADSLAgentCircuitID_Lookup(parsed); err != nil || !bytes.Equal(value, []byte("old")) {
				t.Fatalf("original value lost: %q, %v", value, err)
			}
			if value, err := ADSLAgentRemoteID_Lookup(parsed); err != nil || !bytes.Equal(value, []byte("keep")) {
				t.Fatalf("unrelated value lost: %q, %v", value, err)
			}
		})
	}
}

func TestVendorValueLengthBoundary(t *testing.T) {
	for _, length := range []int{1, 246, 247, 248, 253} {
		for _, set := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/set=%v", length, set), func(t *testing.T) {
				p := radius.New(radius.CodeAccessRequest, []byte("secret"))
				value := bytes.Repeat([]byte{'x'}, length)
				var err error
				if set {
					err = ADSLAgentCircuitID_Set(p, value)
				} else {
					err = ADSLAgentCircuitID_Add(p, value)
				}
				if length > 247 {
					if err == nil || len(p.Attributes) != 0 {
						t.Fatalf("oversized value: error %v, attributes %v", err, p.Attributes)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				wire, err := p.Encode()
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := radius.Parse(wire, p.Secret)
				if err != nil {
					t.Fatal(err)
				}
				got, err := ADSLAgentCircuitID_Lookup(parsed)
				if err != nil || !bytes.Equal(got, value) {
					t.Fatalf("round trip: %q, %v", got, err)
				}
			})
		}
	}
}
