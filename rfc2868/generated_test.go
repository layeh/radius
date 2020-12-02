package rfc2868

import (
	"bytes"
	"testing"

	"layeh.com/radius"
)

func Test_TunnelPasswordAdd(t *testing.T) {
	for i := 1; i <= 10; i++ { // 10 times to test random salt generator
		request := radius.New(radius.CodeAccessRequest, []byte("secretly"))

		response := request.Response(radius.CodeAccessAccept)
		password := []byte{0x00, 0x01, 0xde, 0xaf, 0x0B, 0x00, 0x00, 0x07}
		if err := TunnelPassword_Add(response, 0, password); err != nil {
			t.Fatalf("TunnelPassword_Add unexpected err iteration %d: %s", i, err)
		}
		responseRaw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}

		response, err = radius.Parse(responseRaw, request.Secret)
		if err != nil {
			t.Fatal(err)
		}

		_, returned, err := TunnelPassword_Lookup(response, request)
		if err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if !bytes.Equal(returned, password) {
			t.Fatalf("decrypted password does not match encrypted")
		}
	}
}

func Test_TunnelPasswordSet(t *testing.T) {
	for i := 1; i <= 10; i++ { // 10 times to test random salt generator
		request := radius.New(radius.CodeAccessRequest, []byte("secretly"))

		response := request.Response(radius.CodeAccessAccept)
		password := []byte{0x00, 0x01, 0xde, 0xaf, 0x0B, 0x00, 0x00, 0x07}
		if err := TunnelPassword_Set(response, 0, password); err != nil {
			t.Fatalf("TunnelPassword_Set unexpected err iteration %d: %s", i, err)
		}
		responseRaw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}

		response, err = radius.Parse(responseRaw, request.Secret)
		if err != nil {
			t.Fatal(err)
		}

		_, returned, err := TunnelPassword_Lookup(response, request)
		if err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if !bytes.Equal(returned, password) {
			t.Fatalf("decrypted password does not match encrypted")
		}
	}
}

func Test_TunnelPasswordSetString(t *testing.T) {
	for i := 1; i <= 10; i++ { // 10 times to test random salt generator
		request := radius.New(radius.CodeAccessRequest, []byte("secretly"))

		response := request.Response(radius.CodeAccessAccept)
		password := "TunnelPassword"
		if err := TunnelPassword_SetString(response, 0, password); err != nil {
			t.Fatalf("TunnelPassword_SetString unexpected err iteration %d: %s", i, err)
		}
		responseRaw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}

		response, err = radius.Parse(responseRaw, request.Secret)
		if err != nil {
			t.Fatal(err)
		}

		_, returned, err := TunnelPassword_LookupString(response, request)
		if err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if returned != password {
			t.Fatalf("decrypted password does not match encrypted")
		}
	}
}

func Test_TunnelPasswordAddString(t *testing.T) {
	for i := 1; i <= 10; i++ { // 10 times to test random salt generator
		request := radius.New(radius.CodeAccessRequest, []byte("secretly"))

		response := request.Response(radius.CodeAccessAccept)
		password := "TunnelPassword"
		if err := TunnelPassword_AddString(response, 0, password); err != nil {
			t.Fatalf("TunnelPassword_AddString unexpected err iteration %d: %s", i, err)
		}
		responseRaw, err := response.Encode()
		if err != nil {
			t.Fatal(err)
		}

		response, err = radius.Parse(responseRaw, request.Secret)
		if err != nil {
			t.Fatal(err)
		}

		_, returned, err := TunnelPassword_LookupString(response, request)
		if err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if returned != password {
			t.Fatalf("decrypted password does not match encrypted")
		}
	}
}

func Test_Tags(t *testing.T) {
	{
		p := &radius.Packet{}
		if err := TunnelType_Set(p, 11, TunnelType_Value_IP); err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if value, expected := []byte(p.Get(TunnelType_Type)), []byte{0x0B, 0x00, 0x00, 0x07}; !bytes.Equal(value, expected) {
			t.Fatalf("got %v, expected %v", value, expected)
		}
	}

	{
		p := &radius.Packet{}
		if err := TunnelAssignmentID_SetString(p, 4, "alt"); err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if value, expected := []byte(p.Get(TunnelAssignmentID_Type)), []byte{0x04, 'a', 'l', 't'}; !bytes.Equal(value, expected) {
			t.Fatalf("got %v, expected %v", value, expected)
		}
	}

	{
		p := &radius.Packet{}
		if err := TunnelAssignmentID_SetString(p, 0, "alt"); err != nil {
			t.Fatalf("unexpected err: %s", err)
		}
		if value, expected := []byte(p.Get(TunnelAssignmentID_Type)), []byte{0x00, 'a', 'l', 't'}; !bytes.Equal(value, expected) {
			t.Fatalf("got %v, expected %v", value, expected)
		}
	}
}
