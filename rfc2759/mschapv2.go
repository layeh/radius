package rfc2759

import (
	"crypto/des"
	"crypto/sha1"
	"encoding/hex"
	"math/bits"
	"strings"

	//lint:ignore SA1019 compatibility with legacy systems
	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

// ToUTF16 takes an ASCII string and turns it into a UCS-2 / UTF-16 representation
func ToUTF16(in []byte) ([]byte, error) {
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	pwd, err := encoder.Bytes(in)
	if err != nil {
		return nil, err
	}
	return pwd, nil
}

// GenerateNTResponse - rfc2759, 8.1
func GenerateNTResponse(authenticatorChallenge, peerChallenge, username, password []byte) ([]byte, error) {
	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, username)
	ucs2Password, err := ToUTF16(password)
	if err != nil {
		return nil, err
	}
	passwordHash := NTPasswordHash(ucs2Password)

	return ChallengeResponse(challenge, passwordHash), nil
}

// ChallengeHash - rfc2759, 8.2
func ChallengeHash(peerChallenge, authenticatorChallenge, username []byte) []byte {
	sha := sha1.New()
	sha.Write(peerChallenge)
	sha.Write(authenticatorChallenge)
	sha.Write(username)
	return sha.Sum(nil)[:8]
}

// NTPasswordHash with MD4 - rfc2759, 8.3
func NTPasswordHash(password []byte) []byte {
	h := md4.New()
	h.Write(password)
	return h.Sum(nil)
}

// ChallengeResponse - rfc2759, 8.5
func ChallengeResponse(challenge, passwordHash []byte) []byte {
	zPasswordHash := make([]byte, 21)
	copy(zPasswordHash, passwordHash)

	challengeResponse := make([]byte, 24)
	copy(challengeResponse[0:], DESCrypt(zPasswordHash[0:7], challenge))
	copy(challengeResponse[8:], DESCrypt(zPasswordHash[7:14], challenge))
	copy(challengeResponse[16:], DESCrypt(zPasswordHash[14:21], challenge))

	return challengeResponse
}

// parityPadDESKey transforms a 7-octet key into an 8-octed one by
// adding a parity at every 8th bit position.
// See https://limbenjamin.com/articles/des-key-parity-bit-calculator.html
func parityPadDESKey(inBytes []byte) []byte {
	in := uint64(0)
	outBytes := make([]byte, 8)

	for i := 0; i < len(inBytes); i++ {
		offset := uint64(8 * (len(inBytes) - i - 1))
		in |= uint64(inBytes[i]) << offset
	}

	for i := 0; i < len(outBytes); i++ {
		offset := uint64(7 * (len(outBytes) - i - 1))
		outBytes[i] = byte(in>>offset) << 1

		if bits.OnesCount(uint(outBytes[i]))%2 == 0 {
			outBytes[i] |= 1
		}
	}

	return outBytes
}

// DESCrypt - rfc2759, 8.6
func DESCrypt(key, clear []byte) []byte {
	k := key
	if len(k) == 7 {
		k = parityPadDESKey(key)
	}

	cipher, err := des.NewCipher(k)
	if err != nil {
		panic(err)
	}

	b := make([]byte, 8)
	cipher.Encrypt(b, clear)

	return b
}

var (
	magic1 = []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
	}

	magic2 = []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E,
	}
)

// GenerateAuthenticatorResponse - rfc2759, 8.7
func GenerateAuthenticatorResponse(authenticatorChallenge, peerChallenge, ntResponse, username, password []byte) (string, error) {
	ucs2Password, err := ToUTF16(password)
	if err != nil {
		return "", err
	}

	passwordHash := NTPasswordHash(ucs2Password)
	passwordHashHash := NTPasswordHash(passwordHash)

	sha := sha1.New()
	sha.Write(passwordHashHash)
	sha.Write(ntResponse)
	sha.Write(magic1)
	digest := sha.Sum(nil)

	challenge := ChallengeHash(peerChallenge, authenticatorChallenge, username)

	sha = sha1.New()
	sha.Write(digest)
	sha.Write(challenge)
	sha.Write(magic2)
	digest = sha.Sum(nil)

	return "S=" + strings.ToUpper(hex.EncodeToString(digest)), nil
}
