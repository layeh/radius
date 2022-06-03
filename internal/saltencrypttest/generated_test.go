package saltencrypttest

import (
	"bytes"
	"net"
	"testing"

	"layeh.com/radius"
)

func TestEncryptedAttributes(t *testing.T) {
	request := radius.New(radius.CodeAccessRequest, []byte("secretly"))

	response := request.Response(radius.CodeAccessAccept)
	valueInteger := SEInteger(12351)
	if err := SEInteger_Add(response, valueInteger); err != nil {
		t.Fatalf("SEInteger_Add unexpected err: %s", err)
	}
	valueBytes := []byte{0x11, 0x53, 'Q', 'B', 'F'}
	if err := SEOctets_Add(response, valueBytes); err != nil {
		t.Fatalf("SEOctets_Add unexpected err: %s", err)
	}
	valueIP := net.IPv4(10, 0, 51, 2)
	if err := SEIPAddr_Set(response, valueIP); err != nil {
		t.Fatalf("SEIPAddr_Set unexpected err: %s", err)
	}
	responseRaw, err := response.Encode()
	if err != nil {
		t.Fatal(err)
	}

	response, err = radius.Parse(responseRaw, request.Secret)
	if err != nil {
		t.Fatal(err)
	}

	if value, err := SEInteger_Lookup(response, request); err != nil {
		t.Fatalf("unexpected err: %s", err)
	} else if value != valueInteger {
		t.Fatalf("decrypted integer (%d) does not match encrypted (%d)", value, valueInteger)
	}

	if value, err := SEOctets_Lookup(response, request); err != nil {
		t.Fatalf("unexpected err: %s", err)
	} else if !bytes.Equal(value, valueBytes) {
		t.Fatalf("decrypted octets (%#v) does not match encrypted (%#v)", value, valueBytes)
	}

	if value, err := SEIPAddr_Lookup(response, request); err != nil {
		t.Fatalf("unexpected err: %s", err)
	} else if !valueIP.Equal(value) {
		t.Fatalf("decrypted IP (%v) does not match encrypted (%v)", value, valueIP)
	}
}
