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
		Password      string
		EncodedLength int
	}{
		{"", 16},
		{"abc", 16},
		{"0123456789abcde", 16},
		{"0123456789abcdef", 16},
		{"0123456789abcdef0", 16 * 2},
		{"0123456789abcdef0123456789abcdef0123456789abcdef", 16 * 3},
	}

	secret := []byte(`12345`)
	ra := []byte(`0123456789abcdef`)

	for _, x := range tbl {
		attr, err := NewUserPassword([]byte(x.Password), secret, ra)
		if err != nil {
			t.Fatal(err)
		}
		if len(attr) != x.EncodedLength {
			t.Fatalf("expected encoded length of %#v = %d, got %d", x.Password, x.EncodedLength, len(attr))
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

			if enc := hex.EncodeToString([]byte(attr)); tt.Expected != enc {
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
