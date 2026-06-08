package rfc2869

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"

	"layeh.com/radius"
)

const messageAuthenticatorValueLength = 16

// ErrNoMessageAuthenticator is returned when a packet does not contain a
// Message-Authenticator attribute.
var ErrNoMessageAuthenticator = errors.New("rfc2869: no Message-Authenticator attribute")

// ErrInvalidMessageAuthenticator is returned by ValidateMessageAuthenticator
// when a packet's Message-Authenticator attribute does not match the expected
// HMAC-MD5 value.
var ErrInvalidMessageAuthenticator = errors.New("rfc2869: invalid Message-Authenticator")

// AddMessageAuthenticator adds a zeroed, correctly sized Message-Authenticator
// attribute to p, replacing any existing one.
//
// The placeholder attribute must be present before the packet is encoded so
// that SignMessageAuthenticator can fill in the computed value over the final
// wire bytes.
func AddMessageAuthenticator(p *radius.Packet) {
	var zero [messageAuthenticatorValueLength]byte
	_ = MessageAuthenticator_Set(p, zero[:])
}

// SignMessageAuthenticator computes the Message-Authenticator (RFC 3579,
// Section 3.2) for the encoded RADIUS packet contained in wire and writes it
// into the packet's Message-Authenticator attribute.
//
// wire must be a fully encoded RADIUS packet that already contains a 16-octet
// Message-Authenticator attribute (use AddMessageAuthenticator before encoding).
// secret is the shared secret used as the HMAC-MD5 key.
//
// The HMAC is computed over the entire packet with the Message-Authenticator
// value treated as zero, using the Authenticator field currently present in
// wire. This is exactly the required computation for Access-Request and
// Status-Server packets. For response packets, set the Authenticator field to
// the corresponding request's Authenticator before signing and compute the
// Response Authenticator afterwards.
func SignMessageAuthenticator(wire, secret []byte) error {
	offset, err := messageAuthenticatorValueOffset(wire)
	if err != nil {
		return err
	}
	sum := computeMessageAuthenticator(wire, secret, offset)
	copy(wire[offset:offset+messageAuthenticatorValueLength], sum)
	return nil
}

// ValidateMessageAuthenticator verifies the Message-Authenticator attribute
// (RFC 3579, Section 3.2) of the encoded RADIUS packet contained in wire,
// using secret as the HMAC-MD5 key.
//
// It returns nil if the attribute is present and valid,
// ErrNoMessageAuthenticator if the packet has no Message-Authenticator
// attribute, ErrInvalidMessageAuthenticator if the attribute does not match,
// or another error if wire is malformed.
//
// The Authenticator field present in wire is used as the HMAC input, which is
// correct for Access-Request and Status-Server packets. To validate a response
// packet, set the Authenticator field to the request's Authenticator first.
func ValidateMessageAuthenticator(wire, secret []byte) error {
	offset, err := messageAuthenticatorValueOffset(wire)
	if err != nil {
		return err
	}
	sum := computeMessageAuthenticator(wire, secret, offset)
	if !hmac.Equal(sum, wire[offset:offset+messageAuthenticatorValueLength]) {
		return ErrInvalidMessageAuthenticator
	}
	return nil
}

// messageAuthenticatorValueOffset returns the offset within wire of the 16-octet
// Message-Authenticator value.
func messageAuthenticatorValueOffset(wire []byte) (int, error) {
	if len(wire) < 20 {
		return 0, errors.New("rfc2869: packet not at least 20 bytes long")
	}
	length := int(binary.BigEndian.Uint16(wire[2:4]))
	if length < 20 || length > len(wire) {
		return 0, errors.New("rfc2869: invalid packet length")
	}

	for i := 20; i < length; {
		if i+2 > length {
			return 0, errors.New("rfc2869: invalid attribute")
		}
		attrLength := int(wire[i+1])
		if attrLength < 2 || i+attrLength > length {
			return 0, errors.New("rfc2869: invalid attribute length")
		}
		if radius.Type(wire[i]) == MessageAuthenticator_Type {
			if attrLength != 2+messageAuthenticatorValueLength {
				return 0, errors.New("rfc2869: invalid Message-Authenticator length")
			}
			return i + 2, nil
		}
		i += attrLength
	}

	return 0, ErrNoMessageAuthenticator
}

// computeMessageAuthenticator returns the HMAC-MD5 over wire (up to its declared
// length) with the 16 octets at valueOffset treated as zero.
func computeMessageAuthenticator(wire, secret []byte, valueOffset int) []byte {
	length := int(binary.BigEndian.Uint16(wire[2:4]))

	mac := hmac.New(md5.New, secret)
	mac.Write(wire[:valueOffset])
	var zero [messageAuthenticatorValueLength]byte
	mac.Write(zero[:])
	mac.Write(wire[valueOffset+messageAuthenticatorValueLength : length])
	return mac.Sum(nil)
}
