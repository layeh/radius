package rfc2869

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"testing"

	"layeh.com/radius"
)

func encodeWithMessageAuthenticator(t *testing.T, code radius.Code, secret []byte) []byte {
	t.Helper()

	p := radius.New(code, secret)
	p.Add(radius.Type(1), radius.Attribute("user")) // User-Name
	AddMessageAuthenticator(p)
	p.Add(radius.Type(4), radius.Attribute{192, 0, 2, 1}) // NAS-IP-Address

	wire, err := p.Encode()
	if err != nil {
		t.Fatalf("encode: %s", err)
	}
	return wire
}

func TestMessageAuthenticator_SignAndValidate(t *testing.T) {
	secret := []byte("s3cr3t")

	for _, code := range []radius.Code{radius.CodeAccessRequest, radius.CodeStatusServer} {
		wire := encodeWithMessageAuthenticator(t, code, secret)

		if err := SignMessageAuthenticator(wire, secret); err != nil {
			t.Fatalf("code %v: sign: %s", code, err)
		}

		if err := ValidateMessageAuthenticator(wire, secret); err != nil {
			t.Fatalf("code %v: validate after sign: %s", code, err)
		}

		// Independently recompute the HMAC over the packet with the
		// Message-Authenticator value zeroed and confirm it matches what Sign
		// wrote.
		offset, err := messageAuthenticatorValueOffset(wire)
		if err != nil {
			t.Fatalf("code %v: offset: %s", code, err)
		}
		length := int(binary.BigEndian.Uint16(wire[2:4]))
		check := make([]byte, length)
		copy(check, wire[:length])
		for i := offset; i < offset+messageAuthenticatorValueLength; i++ {
			check[i] = 0
		}
		mac := hmac.New(md5.New, secret)
		mac.Write(check)
		if !hmac.Equal(mac.Sum(nil), wire[offset:offset+messageAuthenticatorValueLength]) {
			t.Fatalf("code %v: signed value does not match independent HMAC", code)
		}
	}
}

func TestMessageAuthenticator_ValidateTampered(t *testing.T) {
	secret := []byte("s3cr3t")
	wire := encodeWithMessageAuthenticator(t, radius.CodeAccessRequest, secret)
	if err := SignMessageAuthenticator(wire, secret); err != nil {
		t.Fatal(err)
	}

	// Flip a bit in the packet body (the User-Name value).
	tampered := make([]byte, len(wire))
	copy(tampered, wire)
	tampered[22] ^= 0x01
	if err := ValidateMessageAuthenticator(tampered, secret); !errors.Is(err, ErrInvalidMessageAuthenticator) {
		t.Fatalf("got err %v; expected ErrInvalidMessageAuthenticator", err)
	}

	// A different secret must not validate.
	if err := ValidateMessageAuthenticator(wire, []byte("other")); !errors.Is(err, ErrInvalidMessageAuthenticator) {
		t.Fatalf("got err %v; expected ErrInvalidMessageAuthenticator", err)
	}
}

func TestMessageAuthenticator_Missing(t *testing.T) {
	secret := []byte("s3cr3t")

	p := radius.New(radius.CodeAccessRequest, secret)
	p.Add(radius.Type(1), radius.Attribute("user"))
	wire, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateMessageAuthenticator(wire, secret); !errors.Is(err, ErrNoMessageAuthenticator) {
		t.Fatalf("validate got err %v; expected ErrNoMessageAuthenticator", err)
	}
	if err := SignMessageAuthenticator(wire, secret); !errors.Is(err, ErrNoMessageAuthenticator) {
		t.Fatalf("sign got err %v; expected ErrNoMessageAuthenticator", err)
	}
}

func TestMessageAuthenticator_Malformed(t *testing.T) {
	if err := ValidateMessageAuthenticator([]byte{0x01, 0x02}, []byte("x")); err == nil {
		t.Fatal("expected error for short packet")
	}
}
