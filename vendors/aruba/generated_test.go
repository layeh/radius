package aruba_test

import (
	"testing"

	"layeh.com/radius"
	. "layeh.com/radius/vendors/aruba"
)

func TestLookup(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte(`12345`))
	ArubaUserRole_SetString(p, "Admin")
	ArubaDeviceType_SetString(p, "Desktop")

	if dt := ArubaDeviceType_GetString(p); dt != "Desktop" {
		t.Fatalf("ArubaDeviceType = %v; expecting %v", dt, "Desktop")
	}
}

func TestVendorDel(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte(`12345`))
	ArubaUserRole_AddString(p, "User")
	ArubaUserRole_AddString(p, "Admin")
	ArubaDeviceType_AddString(p, "Laptop")
	ArubaUserRole_Del(p)

	if values, err := ArubaUserRole_GetStrings(p); err != nil {
		t.Fatalf("got error %v; want none", err)
	} else if len(values) != 0 {
		t.Fatalf("got values = %v; want none", values)
	}

	if value := ArubaDeviceType_GetString(p); value != "Laptop" {
		t.Fatalf("got Device Type = %v; want Laptop", value)
	}
	ArubaDeviceType_Del(p)

	if encoded, err := p.Encode(); err != nil {
		t.Fatalf("got error %v; want none", err)
	} else if len(encoded) != 20 {
		t.Fatalf("got encoded length %d; want 20", len(encoded))
	}
}
