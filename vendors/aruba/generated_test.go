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
