package radius

import (
	"bytes"
	"crypto/md5"
	"errors"
)

func init() {
	builtinOnce.Do(initDictionary)
	// TODO: Attribute* should be initialized before
	Builtin.MustRegister("User-Name", 1, AttributeText)
	Builtin.MustRegister("User-Password", 2, rfc2865UserPassword{})
	Builtin.MustRegister("CHAP-Password", 3, AttributeString)
	Builtin.MustRegister("NAS-IP-Address", 4, AttributeAddress)
	Builtin.MustRegister("NAS-Port", 5, AttributeInteger)
	Builtin.MustRegister("Service-Type", 6, AttributeInteger)
	Builtin.MustRegister("Framed-Protocol", 7, AttributeInteger)
	Builtin.MustRegister("Framed-IP-Address", 8, AttributeAddress)
	Builtin.MustRegister("Framed-IP-Netmask", 9, AttributeAddress)
	Builtin.MustRegister("Framed-Routing", 10, AttributeInteger)
	Builtin.MustRegister("Filter-Id", 11, AttributeText)
	Builtin.MustRegister("Framed-MTU", 12, AttributeInteger)
	Builtin.MustRegister("Framed-Compression", 13, AttributeInteger)
	Builtin.MustRegister("Login-IP-Host", 14, AttributeAddress)
	Builtin.MustRegister("Login-Service", 15, AttributeInteger)
	Builtin.MustRegister("Login-TCP-Port", 16, AttributeInteger)
	Builtin.MustRegister("Reply-Message", 18, AttributeText)
	Builtin.MustRegister("Callback-Number", 19, AttributeString)
	Builtin.MustRegister("Callback-Id", 20, AttributeString)
	Builtin.MustRegister("Framed-Route", 22, AttributeText)
	Builtin.MustRegister("Framed-IPX-Network", 23, AttributeAddress)
	Builtin.MustRegister("State", 24, AttributeString)
	Builtin.MustRegister("Class", 25, AttributeString)
	Builtin.MustRegister("Vendor-Specific", 26, AttributeString)
	Builtin.MustRegister("Session-Timeout", 27, AttributeInteger)
	Builtin.MustRegister("Idle-Timeout", 28, AttributeInteger)
	Builtin.MustRegister("Termination-Action", 29, AttributeInteger)
	Builtin.MustRegister("Called-Station-Id", 30, AttributeString)
	Builtin.MustRegister("Calling-Station-Id", 31, AttributeString)
	Builtin.MustRegister("NAS-Identifier", 32, AttributeString)
	Builtin.MustRegister("Proxy-State", 33, AttributeString)
	Builtin.MustRegister("Login-LAT-Service", 34, AttributeString)
	Builtin.MustRegister("Login-LAT-Node", 35, AttributeString)
	Builtin.MustRegister("Login-LAT-Group", 36, AttributeString)
	Builtin.MustRegister("Framed-AppleTalk-Link", 37, AttributeInteger)
	Builtin.MustRegister("Framed-AppleTalk-Network", 38, AttributeInteger)
	Builtin.MustRegister("Framed-AppleTalk-Zone", 39, AttributeString)
	Builtin.MustRegister("CHAP-Challenge", 60, AttributeString)
	Builtin.MustRegister("NAS-Port-Type", 61, AttributeInteger)
	Builtin.MustRegister("Port-Limit", 62, AttributeInteger)
	Builtin.MustRegister("Login-LAT-Port", 63, AttributeString)
}

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
