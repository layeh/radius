package rfc2868

import (
	"bytes"
	"testing"

	"layeh.com/radius"
)

func Test_Tags(t *testing.T) {
	{
		p := &radius.Packet{
			Attributes: make(radius.Attributes),
		}
		if err := TunnelType_Set(p, 11, TunnelType_Value_IP); err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if value, expected := []byte(p.Get(TunnelType_Type)), []byte{0x0B, 0x00, 0x00, 0x07}; !bytes.Equal(value, expected) {
			t.Fatalf("got %v, expected %v", value, expected)
		}
	}

	{
		p := &radius.Packet{
			Attributes: make(radius.Attributes),
		}
		if err := TunnelAssignmentID_SetString(p, 4, "alt"); err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if value, expected := []byte(p.Get(TunnelAssignmentID_Type)), []byte{0x04, 'a', 'l', 't'}; !bytes.Equal(value, expected) {
			t.Fatalf("got %v, expected %v", value, expected)
		}
	}

	{
		p := &radius.Packet{
			Attributes: make(radius.Attributes),
		}
		if err := TunnelAssignmentID_SetString(p, 0, "alt"); err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if value, expected := []byte(p.Get(TunnelAssignmentID_Type)), []byte{0x00, 'a', 'l', 't'}; !bytes.Equal(value, expected) {
			t.Fatalf("got %v, expected %v", value, expected)
		}
	}
}
