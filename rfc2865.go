package radius

import (
	"bytes"
	"crypto/md5"
	"errors"
)

// TODO: support User-Password attributes longer than 16 bytes
type rfc2865UserPassword struct{}

func (rfc2865UserPassword) Decode(p *Packet, value []byte) (interface{}, error) {
	if p.Secret == nil {
		return nil, errors.New("radius: User-Password attribute requires Packet.Secret")
	}
	if len(value) != 16 {
		return nil, errors.New("radius: invalid User-Password attribute length")
	}
	v := make([]byte, len(value))
	copy(v, value)

	var mask [md5.Size]byte
	hash := md5.New()
	hash.Write(p.Secret)
	hash.Write(p.Authenticator[:])
	hash.Sum(mask[0:0])

	for i, b := range v {
		v[i] = b ^ mask[i]
	}

	if i := bytes.IndexByte(v, 0); i > -1 {
		return string(v[:i]), nil
	}
	return string(v), nil
}

func (rfc2865UserPassword) Encode(p *Packet, value interface{}) ([]byte, error) {
	if p.Secret == nil {
		return nil, errors.New("radius: User-Password attribute requires Packet.Secret")
	}
	var password []byte
	if bytePassword, ok := value.([]byte); !ok {
		strPassword, ok := value.(string)
		if !ok {
			return nil, errors.New("radius: User-Password attribute must be string or []byte")
		}
		password = []byte(strPassword)
	} else {
		password = bytePassword
	}

	if len(password) > 16 {
		return nil, errors.New("radius: invalid User-Password attribute length")
	}

	var mask [md5.Size]byte
	hash := md5.New()
	hash.Write(p.Secret)
	hash.Write(p.Authenticator[:])
	hash.Sum(mask[0:0])

	for i, b := range password {
		mask[i] = b ^ mask[i]
	}

	return mask[:], nil
}
