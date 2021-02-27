package crypto

import (
	"github.com/fxamacker/cbor/v2"
)

// COSEKey, as defined per https://tools.ietf.org/html/rfc8152#section-7.1
// Only supports Elliptic Curve Public keys.
type COSEKey struct {
	Y     []byte    `cbor:"-3,keyasint,omitempty"`
	X     []byte    `cbor:"-2,keyasint,omitempty"`
	Curve CurveType `cbor:"-1,keyasint,omitempty"`

	KeyType KeyType        `cbor:"1,keyasint"`
	KeyID   []byte         `cbor:"2,keyasint,omitempty"`
	Alg     Alg            `cbor:"3,keyasint,omitempty"`
	KeyOps  []KeyOperation `cbor:"4,keyasint,omitempty"`
	BaseIV  []byte         `cbor:"5,keyasint,omitempty"`
}

func (k *COSEKey) CBOREncode() ([]byte, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	return enc.Marshal(k)
}

// KeyType defines a key type from https://tools.ietf.org/html/rfc8152#section-13
type KeyType int

const (
	// OKP is an Octet Key Pair
	OKP KeyType = 0x01
	// EC2 is an Elliptic Curve Key
	EC2 KeyType = 0x02
)

type CurveType int

const (
	P256    CurveType = 0x01
	P384    CurveType = 0x02
	P521    CurveType = 0x03
	X25519  CurveType = 0x04
	X448    CurveType = 0x05
	Ed25519 CurveType = 0x06
	Ed448   CurveType = 0x07
)

type KeyOperation int

const (
	Sign KeyOperation = iota + 1
	Verify
	Encrypt
	Decrypt
	WrapKey
	UnwrapKey
	DeriveKey
	DeriveBits
	MACCreate
	MACVerify
)

// Alg must be the value of one of the algorithms registered in
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms.
type Alg int

const (
	RS256          Alg = -257 // RSASSA-PKCS1-v1_5 using SHA-256
	PS256          Alg = -37  // RSASSA-PSS w/ SHA-256
	ECDHES_HKDF256 Alg = -25  // ECDH-ES + HKDF-256
	ES256          Alg = -7   // ECDSA w/ SHA-256
)
