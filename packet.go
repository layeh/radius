package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// MaxPacketLength is the maximum wire length of a RADIUS packet.
const MaxPacketLength = 4095

// MessageAuthneticatorAttrSize Size of the Message-Authenticator attribute, including headers
const MessageAuthneticatorAttrSize = 18

// RadiusMessageHeaderSize size of RADIUS message header, including Request-Authenticator
const RadiusMessageHeaderSize = 20

// MessageAuthenticator_Type hard-code the value as referncing the rfc2869 pakcage
// creates circular dependency
const MessageAuthenticator_Type = 80

// EAPMessage_Type hard-code the value as referncing the rfc2869 pakcage
// creates circular dependency
const EAPMessage_Type = 79

// Packet is a RADIUS packet.
type Packet struct {
	Code          Code
	Identifier    byte
	Authenticator [16]byte
	Secret        []byte
	Attributes
}

// New creates a new packet with the Code, Secret fields set to the given
// values. The returned packet's Identifier and Authenticator fields are filled
// with random values.
//
// The function panics if not enough random data could be generated.
func New(code Code, secret []byte) *Packet {
	var buff [17]byte
	if _, err := rand.Read(buff[:]); err != nil {
		panic(err)
	}

	packet := &Packet{
		Code:       code,
		Identifier: buff[0],
		Secret:     secret,
		Attributes: make(Attributes),
	}
	copy(packet.Authenticator[:], buff[1:])
	return packet
}

// Parse parses an encoded RADIUS packet b. An error is returned if the packet
// is malformed.
func Parse(b, secret []byte) (*Packet, error) {
	if len(b) < RadiusMessageHeaderSize {
		return nil, errors.New("radius: packet not at least 20 bytes long")
	}

	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < RadiusMessageHeaderSize || length > MaxPacketLength || len(b) != length {
		return nil, errors.New("radius: invalid packet length")
	}

	attrs, err := ParseAttributes(b[RadiusMessageHeaderSize:])
	if err != nil {
		return nil, err
	}

	packet := &Packet{
		Code:       Code(b[0]),
		Identifier: b[1],
		Secret:     secret,
		Attributes: attrs,
	}
	copy(packet.Authenticator[:], b[4:20])
	return packet, nil
}

// Response returns a new packet that has the same identifier, secret, and
// authenticator as the current packet.
func (p *Packet) Response(code Code) *Packet {
	q := &Packet{
		Code:       code,
		Identifier: p.Identifier,
		Secret:     p.Secret,
		Attributes: make(Attributes),
	}
	copy(q.Authenticator[:], p.Authenticator[:])
	return q
}

// MessageAuthenticatorRequired indicates whether packet requires Message-Authenticator
// attribute, as per rfc3579 section 3.2 and rfc2869 section 5.14
func (p *Packet) MessageAuthenticatorRequired() bool {
	_, hasEapMessage := p.Lookup(EAPMessage_Type)
	return hasEapMessage &&
		(p.Code == CodeAccessAccept ||
			p.Code == CodeAccessReject ||
			p.Code == CodeAccessChallenge)
}

// Encode encodes the RADIUS packet to wire format. An error is returned if the
// encoded packet is too long (due to its Attributes), or if the packet has an
// unknown Code.
func (p *Packet) Encode() ([]byte, error) {
	size := RadiusMessageHeaderSize

	if p.MessageAuthenticatorRequired() {
		_, msgAuthExists := p.Lookup(MessageAuthenticator_Type)
		if msgAuthExists {
			return nil, errors.New("message authneticator must not be calculated by caller")
		}
		size += MessageAuthneticatorAttrSize
	}

	attributesSize := p.Attributes.wireSize()
	if attributesSize == -1 {
		return nil, errors.New("invalid packet attribute length")
	}
	size += attributesSize

	if size > MaxPacketLength {
		return nil, errors.New("encoded packet is too long")
	}

	b := make([]byte, size)
	b[0] = byte(p.Code)
	b[1] = byte(p.Identifier)
	binary.BigEndian.PutUint16(b[2:4], uint16(size))
	p.Attributes.encodeTo(b[20:])

	// Calculate Message-Authenticator
	if p.MessageAuthenticatorRequired() {
		// copy request authenticator
		copy(b[4:20], p.Authenticator[:])

		// create a dummy Message-Authenticator
		maValueSize := MessageAuthneticatorAttrSize - 2
		var ma = append(
			[]byte{
				MessageAuthenticator_Type,
				MessageAuthneticatorAttrSize,
			},
			bytes.Repeat([]byte{0x00}, maValueSize)...,
		)

		// calculate
		copy(b[len(b)-MessageAuthneticatorAttrSize:], ma)
		hash := hmac.New(md5.New, p.Secret)
		hash.Write(b)
		b = hash.Sum(b[:len(b)-maValueSize])
	}

	// calculate response-authenticator
	switch p.Code {
	case CodeAccessRequest, CodeStatusServer:
		copy(b[4:20], p.Authenticator[:])
	case CodeAccessAccept, CodeAccessReject, CodeAccountingRequest, CodeAccountingResponse, CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK, CodeCoARequest, CodeAccessChallenge, CodeCoAACK, CodeCoANAK:
		hash := md5.New()
		hash.Write(b[:4])
		switch p.Code {
		case CodeAccountingRequest, CodeDisconnectRequest, CodeCoARequest:
			var nul [16]byte
			hash.Write(nul[:])
		default:
			hash.Write(p.Authenticator[:])
		}
		hash.Write(b[20:])
		hash.Write(p.Secret)
		hash.Sum(b[4:4:20])
	default:
		return nil, errors.New("radius: unknown Packet Code")
	}

	return b, nil
}

// IsAuthenticResponse returns if the given RADIUS response is an authentic
// response to the given request.
func IsAuthenticResponse(response, request, secret []byte) bool {
	if len(response) < 20 || len(request) < 20 || len(secret) == 0 {
		return false
	}

	hash := md5.New()
	hash.Write(response[:4])
	hash.Write(request[4:20])
	hash.Write(response[20:])
	hash.Write(secret)
	var sum [md5.Size]byte
	return bytes.Equal(hash.Sum(sum[:0]), response[4:20])
}

// IsAuthenticRequest returns if the given RADIUS request is an authentic
// request using the given secret.
func IsAuthenticRequest(request, secret []byte) bool {
	if len(request) < 20 || len(secret) == 0 {
		return false
	}

	switch Code(request[0]) {
	case CodeAccessRequest, CodeStatusServer:
		return true
	case CodeAccountingRequest, CodeDisconnectRequest, CodeCoARequest:
		hash := md5.New()
		hash.Write(request[:4])
		var nul [16]byte
		hash.Write(nul[:])
		hash.Write(request[20:])
		hash.Write(secret)
		var sum [md5.Size]byte
		return bytes.Equal(hash.Sum(sum[:0]), request[4:20])
	default:
		return false
	}
}
