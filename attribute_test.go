package radius

import (
	"bytes"
	"crypto/rand"
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
