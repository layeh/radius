package rfc2865

import (
	"crypto/md5"
	"crypto/subtle"

	"layeh.com/radius"
)

// CHAPMatch reports whether the given CHAP-Password value corresponds to
// password and challenge.
//
// chapPassword must be the raw 17-octet CHAP-Password attribute value: a
// 1-octet CHAP identifier followed by the 16-octet MD5 response, as described
// in RFC 1994 and RFC 2865, Section 2.2. challenge is the CHAP challenge,
// i.e. the CHAP-Challenge attribute value, or the request Authenticator when
// the request does not carry a CHAP-Challenge attribute.
//
// The comparison of the expected and received responses is done in constant
// time.
func CHAPMatch(password, chapPassword, challenge []byte) bool {
	if len(chapPassword) != 17 {
		return false
	}

	h := md5.New()
	h.Write(chapPassword[:1]) // CHAP identifier
	h.Write(password)
	h.Write(challenge)

	var sum [md5.Size]byte
	return subtle.ConstantTimeCompare(h.Sum(sum[:0]), chapPassword[1:]) == 1
}

// CHAPVerify reports whether password is the correct password for the CHAP
// authentication carried in p.
//
// It combines the CHAP-Password attribute with the CHAP-Challenge attribute. If
// p does not contain a CHAP-Challenge attribute, the packet's Authenticator is
// used as the challenge, as described in RFC 2865, Section 2.2.
//
// CHAPVerify returns false if p does not contain a validly sized CHAP-Password
// attribute. It only handles standard CHAP (MD5); MS-CHAP and MS-CHAPv2 use
// different attributes and algorithms.
func CHAPVerify(p *radius.Packet, password []byte) bool {
	chapPassword := CHAPPassword_Get(p)
	if len(chapPassword) == 0 {
		return false
	}

	challenge := CHAPChallenge_Get(p)
	if len(challenge) == 0 {
		challenge = p.Authenticator[:]
	}

	return CHAPMatch(password, chapPassword, challenge)
}
