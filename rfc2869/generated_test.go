package rfc2869

import (
	"bytes"
	"testing"

	"layeh.com/radius"
)

func TestEAPMessage(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte(`secret`))

	if v, expect := EAPMessage_Get(p), []byte{}; !bytes.Equal(v, expect) {
		t.Fatalf("got %s; expected %s", v, expect)
	}

	if v, expect := EAPMessage_GetString(p), ""; v != expect {
		t.Fatalf("got %s; expected %s", v, expect)
	}

	_, err := EAPMessage_Lookup(p)
	if err != radius.ErrNoAttribute {
		t.Fatalf("got error %v; expected ErrNoAttribute", err)
	}

	_, err = EAPMessage_LookupString(p)
	if err != radius.ErrNoAttribute {
		t.Fatalf("got error %v; expected ErrNoAttribute", err)
	}

	value := bytes.Repeat([]byte(`radius`), 100)
	if err := EAPMessage_Set(p, value); err != nil {
		t.Fatalf("got unexpected error %v", err)
	}
	if v := EAPMessage_Get(p); !bytes.Equal(v, value) {
		t.Fatalf("got %v; expected %v", v, value)
	}
}
