package radius_test

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/rfc5904"
	"layeh.com/radius/rfc7268"
)

func TestConcatSetReplaces(t *testing.T) {
	for _, attr := range []struct {
		name         string
		typ          radius.Type
		set          func(*radius.Packet, []byte) error
		setString    func(*radius.Packet, string) error
		lookup       func(*radius.Packet) ([]byte, error)
		lookupString func(*radius.Packet) (string, error)
	}{
		{"EAPMessage", rfc2869.EAPMessage_Type, rfc2869.EAPMessage_Set, rfc2869.EAPMessage_SetString, rfc2869.EAPMessage_Lookup, rfc2869.EAPMessage_LookupString},
		{"PKMSSCert", rfc5904.PKMSSCert_Type, rfc5904.PKMSSCert_Set, rfc5904.PKMSSCert_SetString, rfc5904.PKMSSCert_Lookup, rfc5904.PKMSSCert_LookupString},
		{"PKMCACert", rfc5904.PKMCACert_Type, rfc5904.PKMCACert_Set, rfc5904.PKMCACert_SetString, rfc5904.PKMCACert_Lookup, rfc5904.PKMCACert_LookupString},
		{"EAPoLAnnouncement", rfc7268.EAPoLAnnouncement_Type, rfc7268.EAPoLAnnouncement_Set, rfc7268.EAPoLAnnouncement_SetString, rfc7268.EAPoLAnnouncement_Lookup, rfc7268.EAPoLAnnouncement_LookupString},
	} {
		for _, str := range []bool{false, true} {
			for _, size := range []int{0, 1, 253, 254, 506, 507} {
				t.Run(fmt.Sprintf("%s/string=%v/size=%d", attr.name, str, size), func(t *testing.T) {
					p := radius.New(radius.CodeAccessRequest, []byte("secret"))
					// Interleave old fragments with unrelated fields, as on a reused inbound packet.
					p.Attributes.Add(1, []byte("before"))
					p.Attributes.Add(attr.typ, bytes.Repeat([]byte("old"), 80))
					p.Attributes.Add(2, []byte("middle"))
					p.Attributes.Add(attr.typ, []byte("old-tail"))
					p.Attributes.Add(3, []byte("after"))
					p = concatWireRoundTrip(t, p)
					want := make([]byte, size)
					for i := range want {
						want[i] = byte(i)
					}
					var err error
					if str {
						err = attr.setString(p, string(want))
					} else {
						err = attr.set(p, want)
					}
					if err != nil {
						t.Fatal(err)
					}
					for _, current := range []*radius.Packet{p, concatWireRoundTrip(t, p)} {
						got, err := attr.lookup(current)
						if size == 0 {
							if !errors.Is(err, radius.ErrNoAttribute) {
								t.Errorf("cleared lookup: %q, %v", got, err)
							}
						} else if err != nil || !bytes.Equal(got, want) {
							t.Errorf("lookup: %d bytes, %v; want %d replacement bytes", len(got), err, size)
						}
						gotString, stringErr := attr.lookupString(current)
						if size == 0 {
							if !errors.Is(stringErr, radius.ErrNoAttribute) {
								t.Errorf("cleared string lookup: %q, %v", gotString, stringErr)
							}
						} else if stringErr != nil || gotString != string(want) {
							t.Errorf("string lookup: %d bytes, %v; want %d replacement bytes", len(gotString), stringErr, size)
						}
						var unrelated []radius.AVP
						chunks := 0
						for _, avp := range current.Attributes {
							if avp.Type == attr.typ {
								chunks++
								if len(avp.Attribute) > 253 {
									t.Error("oversized chunk")
								}
							} else {
								unrelated = append(unrelated, *avp)
							}
						}
						if chunks != (size+252)/253 {
							t.Errorf("chunks = %d, want %d", chunks, (size+252)/253)
						}
						expected := []radius.AVP{{Type: 1, Attribute: []byte("before")}, {Type: 2, Attribute: []byte("middle")}, {Type: 3, Attribute: []byte("after")}}
						if !reflect.DeepEqual(unrelated, expected) {
							t.Errorf("unrelated fields changed: %v", unrelated)
						}
					}
					// Clear after replacement as well, exercising repeated calls on the same packet.
					if err = attr.set(p, nil); err != nil {
						t.Fatal(err)
					}
					if got, err := attr.lookup(p); !errors.Is(err, radius.ErrNoAttribute) {
						t.Errorf("repeated clear: %q, %v", got, err)
					}
				})
			}
		}
	}
}

func concatWireRoundTrip(t *testing.T, p *radius.Packet) *radius.Packet {
	t.Helper()
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	result, err := radius.Parse(wire, p.Secret)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestConcatSetAliasedValue(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte("secret"))
	p.Attributes.Add(rfc2869.EAPMessage_Type, []byte("first"))
	p.Attributes.Add(1, []byte("unrelated"))
	p.Attributes.Add(rfc2869.EAPMessage_Type, []byte("last"))
	value := p.Attributes[2].Attribute[1:]
	if err := rfc2869.EAPMessage_Set(p, value); err != nil {
		t.Fatal(err)
	}
	if got := rfc2869.EAPMessage_Get(p); string(got) != "ast" {
		t.Errorf("aliased replacement = %q, want ast", got)
	}
	if string(p.Attributes.Get(1)) != "unrelated" {
		t.Error("unrelated attribute changed")
	}
}
