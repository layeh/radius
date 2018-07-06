package radius

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseAttributes_invalid(t *testing.T) {
	tests := []struct {
		Wire  string
		Error string
	}{
		{"\x01", "short buffer"},

		{"\x01\xff", "invalid attribute length"},
		{"\x01\x01", "invalid attribute length"},
	}

	for _, test := range tests {
		attrs, err := ParseAttributes([]byte(test.Wire))
		if len(attrs) != 0 {
			t.Errorf("(%#x): expected empty attrs, got %v", test.Wire, attrs)
		} else if err == nil {
			t.Errorf("(%#x): expected error, got none", test.Wire)
		} else if !strings.Contains(err.Error(), test.Error) {
			t.Errorf("(%#x): expected error %q, got %q", test.Wire, test.Error, err.Error())
		}
	}
}

func TestAttributes_all(t *testing.T) {
	a := make(Attributes)
	a.Add(1, []byte(`A`))
	a.Add(1, []byte(`A.A`))
	a.Add(3, []byte(`C`))

	a.Add(TypeInvalid, []byte(`Invalid`))

	if attr := a.Get(1); !bytes.Equal([]byte(attr), []byte(`A`)) {
		t.Fatalf("got %s; expecting A", attr)
	}

	if attr := a.Get(2); attr != nil {
		t.Fatalf("got %s; expecting nil", attr)
	}
	if attr, ok := a.Lookup(2); attr != nil || ok {
		t.Fatalf("got %s and %v; expecting nil and false", attr, ok)
	}

	a.Del(1)

	n := a.wireSize()
	if n != 3 {
		t.Fatalf("got wireSize = %d; expecting 3", n)
	}

	var encoded [MaxPacketLength]byte
	a.encodeTo(encoded[:])
	if expecting := []byte("\x03\x03C"); !bytes.Equal(encoded[:n], expecting) {
		t.Fatalf("got %x; expecting %x", encoded[:n], expecting)
	}
}

func TestAttributes_encodeTo_deterministic(t *testing.T) {
	var base []byte

	for i := 0; i < 10000; i++ {
		a := make(Attributes)
		a.Add(83, []byte(`C`))
		a.Add(1, []byte(`A`))
		a.Add(1, []byte(`A.A`))
		a.Add(3, []byte(`C`))

		encoded := make([]byte, MaxPacketLength)
		a.encodeTo(encoded)

		if base == nil {
			base = encoded
		} else {
			if !bytes.Equal(base, encoded) {
				t.Fatal("Attributes.encodeTo not deterministic")
			}
		}
	}
}
