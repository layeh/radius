package rfc2865

import (
	"crypto/md5"
	"testing"

	"layeh.com/radius"
)

func makeCHAPPassword(ident byte, password, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{ident})
	h.Write(password)
	h.Write(challenge)

	out := make([]byte, 17)
	out[0] = ident
	copy(out[1:], h.Sum(nil))
	return out
}

func TestCHAPMatch(t *testing.T) {
	password := []byte("hello")
	challenge := []byte("0123456789abcdef")
	chapPassword := makeCHAPPassword(0x42, password, challenge)

	if !CHAPMatch(password, chapPassword, challenge) {
		t.Fatal("CHAPMatch returned false for a valid password")
	}
	if CHAPMatch([]byte("wrong"), chapPassword, challenge) {
		t.Fatal("CHAPMatch returned true for an invalid password")
	}
	if CHAPMatch(password, chapPassword, []byte("different-chal")) {
		t.Fatal("CHAPMatch returned true for a mismatched challenge")
	}
	if CHAPMatch(password, chapPassword[:16], challenge) {
		t.Fatal("CHAPMatch returned true for a malformed CHAP-Password")
	}
}

func TestCHAPVerify_withCHAPChallenge(t *testing.T) {
	secret := []byte("secret")
	password := []byte("testing123")
	challenge := []byte("a-random-challenge")

	p := radius.New(radius.CodeAccessRequest, secret)
	if err := CHAPChallenge_Add(p, challenge); err != nil {
		t.Fatal(err)
	}
	if err := CHAPPassword_Add(p, makeCHAPPassword(0x01, password, challenge)); err != nil {
		t.Fatal(err)
	}

	if !CHAPVerify(p, password) {
		t.Fatal("CHAPVerify returned false for a valid password")
	}
	if CHAPVerify(p, []byte("nope")) {
		t.Fatal("CHAPVerify returned true for an invalid password")
	}
}

func TestCHAPVerify_authenticatorAsChallenge(t *testing.T) {
	secret := []byte("secret")
	password := []byte("testing123")

	p := radius.New(radius.CodeAccessRequest, secret)
	// No CHAP-Challenge attribute: the Authenticator is the challenge.
	if err := CHAPPassword_Add(p, makeCHAPPassword(0x07, password, p.Authenticator[:])); err != nil {
		t.Fatal(err)
	}

	if !CHAPVerify(p, password) {
		t.Fatal("CHAPVerify returned false for a valid password")
	}
	if CHAPVerify(p, []byte("nope")) {
		t.Fatal("CHAPVerify returned true for an invalid password")
	}
}

func TestCHAPVerify_noCHAPPassword(t *testing.T) {
	p := radius.New(radius.CodeAccessRequest, []byte("secret"))
	if CHAPVerify(p, []byte("anything")) {
		t.Fatal("CHAPVerify returned true for a packet without a CHAP-Password")
	}
}
