package mikrotik

import (
	"testing"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestVendorGenerated(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte(`123456`))
	rfc2865.UserName_SetString(p, "User")

	// Used to get stuck in infinite loop
	MikrotikGroup_SetString(p, "Test Value")
	if str := MikrotikGroup_GetString(p); str != "Test Value" {
		t.Fatalf("MikrotikGroup_GetString = %q; expected %q", str, "Test Value")
	}
	MikrotikGroup_AddString(p, "Extra")

	MikrotikGroup_Del(p)
	if result, err := MikrotikGroup_Gets(p); err != nil {
		t.Fatalf("MikrotikGroup_Gets error %q", err)
	} else if len(result) != 0 {
		t.Fatal("MikrotikGroup_Gets unexpected values")
	}
}
