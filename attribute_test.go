package radius

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"net"
	"testing"
)

func TestNewUserPassword_length(t *testing.T) {
	tbl := []struct {
		Password      []byte
		EncodedLength int
	}{
		{append(make([]byte, 0, 0), ""...), 16},
		{append(make([]byte, 0, 15), "abc"...), 16},
		{append(make([]byte, 0, 15), "0123456789abcde"...), 16},
		{append(make([]byte, 0, 16), "0123456789abcdef"...), 16},
		{append(make([]byte, 0, 30), "0123456789abcdef0"...), 16 * 2},
		{append(make([]byte, 0, 48), "0123456789abcdefzzzzzzzzzzzzzzzzQQQQQQQQQQQQQQQQ"...), 16 * 3},
	}

	secret := []byte(`12345`)
	ra := []byte(`0123456789abcdef`)

	for _, x := range tbl {
		attr, err := NewUserPassword(x.Password, secret, ra)
		if err != nil {
			t.Fatal(err)
		}
		if len(attr) != x.EncodedLength {
			t.Fatalf("expected encoded length of %#v = %d, got %d", x.Password, x.EncodedLength, len(attr))
		}

		decoded, err := UserPassword(attr, secret, ra)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded, x.Password) {
			t.Fatalf("expected roundtrip to succeed")
		}
	}
}

func TestTunnelPassword(t *testing.T) {
	roundtrip := []string{
		"",
		"a",
		"Hello",
		"0123456789abcde",
		"0123456789abcdef",
		"0123456789abcdef0123456789abcdef0123456789abcdef",
	}

	salt := []byte{0x83, 0x45}
	secret := []byte("secret")
	var requestAuthenticator [16]byte
	if _, err := rand.Read(requestAuthenticator[:]); err != nil {
		t.Fatal(err)
	}

	for _, password := range roundtrip {
		t.Run(password, func(t *testing.T) {
			password := []byte(password)
			a, err := NewTunnelPassword(password, salt, secret, requestAuthenticator[:])
			if err != nil {
				t.Fatalf("unexpected NewTunnelPassword error %s", err)
			}

			decryptedPassword, decryptedSalt, err := TunnelPassword(a, secret, requestAuthenticator[:])
			if err != nil {
				t.Fatalf("unexpected TunnelPassword error %s", err)
			}

			if !bytes.Equal(password, decryptedPassword) {
				t.Fatalf("got password %s; expecting %s", decryptedPassword, password)
			}

			if !bytes.Equal(salt, decryptedSalt) {
				t.Fatalf("got salt %s; expecting %s", decryptedSalt, salt)
			}
		})
	}
}

func TestIPv6Prefix(t *testing.T) {
	tests := []struct {
		Mask     string
		Expected string
	}{
		{
			Mask:     "3a00::/8",
			Expected: "00083a",
		},
		{
			Mask:     "3A11::/4",
			Expected: "000430",
		},
		{
			Mask:     "3F11::/5",
			Expected: "000538",
		},
	}

	for _, tt := range tests {
		t.Run(tt.Mask, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tt.Mask)
			if err != nil {
				t.Fatal(err)
			}

			attr, err := NewIPv6Prefix(network)
			if err != nil {
				t.Fatal(err)
			}

			if enc := hex.EncodeToString(attr); tt.Expected != enc {
				t.Fatalf("got %s, expected %s", enc, tt.Expected)
			}

			ipNet, err := IPv6Prefix(attr)
			if err != nil {
				t.Fatal(err)
			}
			if !ipNetEquals(network, ipNet) {
				t.Fatalf("got %v, expected %v", ipNet, network)
			}
		})
	}
}

func TestIPv6Prefix_issue118(t *testing.T) {
	ipNet, err := IPv6Prefix([]byte{0x00, 0x40, 0x20, 0x01, 0x15, 0x30, 0x10, 0x0e})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if expected := net.ParseIP("2001:1530:100e::"); !ipNet.IP.Equal(expected) {
		t.Fatalf("got %v, expected %v", ipNet.IP, expected)
	}
	if ones, size := ipNet.Mask.Size(); ones != 64 || size != 128 {
		t.Fatalf("got %v:%v, expected 64, 128", ones, size)
	}
}

func ipNetEquals(a, b *net.IPNet) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	if a.Mask.String() != b.Mask.String() {
		return false
	}
	return a.IP.Equal(b.IP)
}
