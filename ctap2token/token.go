package ctap2token

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	statusSuccess = 0x00

	cmdMakeCredential   = 0x01
	cmdGetAssertion     = 0x02
	cmdGetInfo          = 0x04
	cmdClientPIN        = 0x06
	cmdReset            = 0x07
	cmdGetNextAssertion = 0x08
)

// CTAP2 error status from https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses
var ctap2Status = map[byte]string{
	0x11: "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",
	0x12: "CTAP2_ERR_INVALID_CBOR",
	0x14: "CTAP2_ERR_MISSING_PARAMETER",
	0x15: "CTAP2_ERR_LIMIT_EXCEEDED",
	0x16: "CTAP2_ERR_UNSUPPORTED_EXTENSION",
	0x19: "CTAP2_ERR_CREDENTIAL_EXCLUDED",
	0x21: "CTAP2_ERR_PROCESSING",
	0x22: "CTAP2_ERR_INVALID_CREDENTIAL",
	0x23: "CTAP2_ERR_USER_ACTION_PENDING",
	0x24: "CTAP2_ERR_OPERATION_PENDING",
	0x25: "CTAP2_ERR_NO_OPERATIONS",
	0x26: "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
	0x27: "CTAP2_ERR_OPERATION_DENIED",
	0x28: "CTAP2_ERR_KEY_STORE_FULL",
	0x2A: "CTAP2_ERR_NO_OPERATION_PENDING",
	0x2B: "CTAP2_ERR_UNSUPPORTED_OPTION",
	0x2C: "CTAP2_ERR_INVALID_OPTION",
	0x2D: "CTAP2_ERR_KEEPALIVE_CANCEL",
	0x2E: "CTAP2_ERR_NO_CREDENTIALS",
	0x2F: "CTAP2_ERR_USER_ACTION_TIMEOUT",
	0x30: "CTAP2_ERR_NOT_ALLOWED",
	0x31: "CTAP2_ERR_PIN_INVALID",
	0x32: "CTAP2_ERR_PIN_BLOCKED",
	0x33: "CTAP2_ERR_PIN_AUTH_INVALID",
	0x34: "CTAP2_ERR_PIN_AUTH_BLOCKED",
	0x35: "CTAP2_ERR_PIN_NOT_SET",
	0x36: "CTAP2_ERR_PIN_REQUIRED",
	0x37: "CTAP2_ERR_PIN_POLICY_VIOLATION",
	0x38: "CTAP2_ERR_PIN_TOKEN_EXPIRED",
	0x39: "CTAP2_ERR_REQUEST_TOO_LARGE",
	0x3A: "CTAP2_ERR_ACTION_TIMEOUT",
	0x3B: "CTAP2_ERR_UP_REQUIRED",
	0xDF: "CTAP2_ERR_SPEC_LAST",
	0xE0: "CTAP2_ERR_EXTENSION_FIRST",
	0xEF: "CTAP2_ERR_EXTENSION_LAST",
	0xF0: "CTAP2_ERR_VENDOR_FIRST",
	0xFF: "CTAP2_ERR_VENDOR_LAST",
}

type Device interface {
	// CBOR sends a CBOR encoded message to the device and returns the response.
	CBOR(data []byte) ([]byte, error)
}

// NewToken returns a token that will use Device to communicate with the device.
func NewToken(d Device) *Token {
	return &Token{d: d}
}

// A Token implements the FIDO U2F hardware token messages as defined in the Raw
// Message Formats specification.
type Token struct {
	d Device
}

type MakeCredentialRequest struct {
	ClientDataHash   ClientDataHash         `cbor:"1,keyasint"`
	RP               CredentialRpEntity     `cbor:"2,keyasint"`
	User             CredentialUserEntity   `cbor:"3,keyasint"`
	PubKeyCredParams []CredentialParam      `cbor:"4,keyasint"`
	ExcludeList      []CredentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions       map[string]interface{} `cbor:"6,keyasint,omitempty"`
	Options          AuthenticatorOptions   `cbor:"7,keyasint,omitempty"`
	// PinAuth is the first 16 bytes of HMAC-SHA-256 of clientDataHash using
	// pinToken which platform got from the authenticator
	PinAuth []byte `cbor:"8,keyasint,omitempty"`
	// PinProtocol is the PIN protocol version chosen by the client
	PinProtocol PinProtocolVersion `cbor:"9,keyasint,omitempty"`
}

// ClientDataHash is the hash of the ClientData contextual binding specified by host.
type ClientDataHash []byte

// CredentialRpEntity describes a Relying Party with which
// the new public key credential will be associated.
type CredentialRpEntity struct {
	// ID is valid domain string that identifies the WebAuthn Relying Party.
	ID   string `cbor:"id,omitempty"`
	Name string `cbor:"name,omitempty"`
	Icon string `cbor:"icon,omitempty"`
}

// CredentialUserEntity describes the user account to which
// the new public key credential will be associated at the RP
type CredentialUserEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
	Icon        string `cbor:"icon,omitempty"`
}

type CredentialParam struct {
	Type CredentialType `cbor:"type"`
	Alg  Alg            `cbor:"alg"`
}

var (
	PublicKeyRS256 CredentialParam = CredentialParam{Type: PublicKey, Alg: RS256}
	PublicKeyPS256 CredentialParam = CredentialParam{Type: PublicKey, Alg: PS256}
	PublicKeyES256 CredentialParam = CredentialParam{Type: PublicKey, Alg: ES256}
)

// CredentialType defines the type of credential, as defined in https://www.w3.org/TR/webauthn/#credentialType
type CredentialType string

const (
	PublicKey CredentialType = "public-key"
)

// Alg must be the value of one of the algorithms registered on
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms.
type Alg int

const (
	RS256          Alg = -257 // RSASSA-PKCS1-v1_5 using SHA-256
	PS256          Alg = -37  // RSASSA-PSS w/ SHA-256
	ECDHES_HKDF256 Alg = -25  // ECDH-ES + HKDF-256
	ES256          Alg = -7   // ECDSA w/ SHA-256
)

// CredentialDescriptor defines a credential returned by the authenticator,
// as defined by https://www.w3.org/TR/webauthn/#credential-dictionary
type CredentialDescriptor struct {
	ID         []byte                   `cbor:"id"`
	Type       CredentialType           `cbor:"type"`
	Transports []AuthenticatorTransport `cbor:"transports"`
}

// AuthenticatorTransport defines hints as to how clients might communicate with a particular authenticator,
// as defined by https://www.w3.org/TR/webauthn/#transport.
type AuthenticatorTransport string

const (
	// USB indicates the respective authenticator can be contacted over removable USB.
	USB AuthenticatorTransport = "usb"
	// NFC indicates the respective authenticator can be contacted over Near Field Communication (NFC).
	NFC AuthenticatorTransport = "nfc"
	// BLE indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
	BLE AuthenticatorTransport = "ble"
	// Internal indicates the respective authenticator is contacted using a client device-specific transport.
	Internal AuthenticatorTransport = "internal"
)

type AuthenticatorOptions struct {
	ResidentKey      bool `cbor:"rk,omitempty"`
	UserVerification bool `cbor:"uv,omitempty"`
}

type PinProtocolVersion uint

const (
	PinProtoV1 PinProtocolVersion = 1
)

// MakeCredentialResponse...
// CTAP 2.1 defines Fmt=0x1 and AuthData=0x2 while CTAP 2.0 defines AuthData=0x1 and Fmt=0x2 for some reasons
type MakeCredentialResponse struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData []byte                 `cbor:"2,keyasint"`
	AttSmt   map[string]interface{} `cbor:"3,keyasint"`
}

func (t *Token) MakeCredential(req *MakeCredentialRequest) (*MakeCredentialResponse, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	reqData, err := enc.Marshal(req)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(reqData)+1)
	data = append(data, cmdMakeCredential)
	data = append(data, reqData...)

	resp, err := t.d.CBOR(data)
	if err != nil {
		return nil, err
	}

	respData := &MakeCredentialResponse{}
	if err := unmarshal(resp, respData); err != nil {
		return nil, err
	}

	return respData, nil
}

type GetAssertionRequest struct{}
type GetAssertioNResponse struct{}

func (t *Token) GetAssertion(req *GetAssertionRequest) (*GetAssertioNResponse, error) {
	return nil, nil
}

type GetInfoResponse struct {
	Versions    []string        `cbor:"1,keyasint"`
	Extensions  []string        `cbor:"2,keyasint,omitempty"`
	AAGUID      []byte          `cbor:"3,keyasint"`
	Options     map[string]bool `cbor:"4,keyasint,omitempty"`
	MaxMsgSize  uint            `cbor:"5,keyasint,omitempty"`
	PinProtocol []uint          `cbor:"6,keyasint,omitempty"`
}

func (t *Token) GetInfo() (*GetInfoResponse, error) {
	resp, err := t.d.CBOR([]byte{cmdGetInfo})
	if err != nil {
		return nil, err
	}

	infos := &GetInfoResponse{}
	if err := unmarshal(resp, infos); err != nil {
		return nil, err
	}

	return infos, nil
}

type ClientPINRequest struct {
	PinProtocol  PinProtocolVersion  `cbor:"1,keyasint"`
	SubCommand   ClientPinSubCommand `cbor:"2,keyasint"`
	KeyAgreement *COSEKey            `cbor:"3,keyasint,omitempty"`
	PinAuth      []byte              `cbor:"4,keyasint,omitempty"`
	NewPinEnc    []byte              `cbor:"5,keyasint,omitempty"`
	PinHashEnc   []byte              `cbor:"6,keyasint,omitempty"`
}

type ClientPinSubCommand uint

const (
	GetRetries      ClientPinSubCommand = 0x01
	GetKeyAgreement ClientPinSubCommand = 0x02
	SetPin          ClientPinSubCommand = 0x03
	ChangePin       ClientPinSubCommand = 0x04
	GetPinToken     ClientPinSubCommand = 0x05
)

// COSEKey, as defined per https://tools.ietf.org/html/rfc8152#section-7.1
// Only support Elliptic Curve Public keys for now.
// TODO: find a way to support all key types defined in the RFC
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

// KeyType defines a key type from https://tools.ietf.org/html/rfc8152#section-13
type KeyType int

const (
	// OKP means Octet Key Pair
	OKP KeyType = 0x01
	// EC2 means Elliptic Curve Keys
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

type ClientPINResponse struct {
	KeyAgreement *COSEKey `cbor:"1,keyasint,omitempty"`
	PinToken     []byte   `cbor:"2,keyasint,omitempty"`
	Retries      uint     `cbor:"3,keyasint,omitempty"`
}

func (t *Token) ClientPIN(req *ClientPINRequest) (*ClientPINResponse, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	reqData, err := enc.Marshal(req)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(reqData)+1)
	data = append(data, cmdClientPIN)
	data = append(data, reqData...)

	resp, err := t.d.CBOR(data)
	if err != nil {
		return nil, err
	}

	respData := &ClientPINResponse{}
	if err := unmarshal(resp, respData); err != nil {
		return nil, err
	}

	return respData, nil
}

type ResetRequest struct{}
type ResetResponse struct{}

func (t *Token) Reset(*ResetRequest) (*ResetResponse, error) {
	return nil, nil
}

type GetNextAssertionRequest struct{}
type GetNextAssertionResponse struct{}

func (t *Token) GetNextAssertion(*GetNextAssertionRequest) (*GetNextAssertionResponse, error) {
	return nil, nil
}

func unmarshal(resp []byte, out interface{}) error {
	if len(resp) == 0 || resp[0] != statusSuccess {
		status, ok := ctap2Status[resp[0]]
		if !ok {
			status = fmt.Sprintf("unknown error %x", resp[0])
		}
		return fmt.Errorf("ctap2token: CBOR error: %s", status)
	}

	if err := cbor.Unmarshal(resp[1:], out); err != nil {
		return err
	}

	return nil
}
