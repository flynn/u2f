package ctap2token

import (
	"encoding/binary"
	"errors"
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
	0x01: "CTAP1_ERR_INVALID_COMMAND",
	0x02: "CTAP1_ERR_INVALID_PARAMETER",
	0x03: "CTAP1_ERR_INVALID_LENGTH",
	0x04: "CTAP1_ERR_INVALID_SEQ",
	0x05: "CTAP1_ERR_TIMEOUT",
	0x06: "CTAP1_ERR_CHANNEL_BUSY",
	0x0A: "CTAP1_ERR_LOCK_REQUIRED",
	0x0B: "CTAP1_ERR_INVALID_CHANNEL",
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
	ClientDataHash   ClientDataHash          `cbor:"1,keyasint"`
	RP               CredentialRpEntity      `cbor:"2,keyasint"`
	User             CredentialUserEntity    `cbor:"3,keyasint"`
	PubKeyCredParams []CredentialParam       `cbor:"4,keyasint"`
	ExcludeList      []CredentialDescriptor  `cbor:"5,keyasint,omitempty"`
	Extensions       AuthenticatorExtensions `cbor:"6,keyasint,omitempty"`
	Options          AuthenticatorOptions    `cbor:"7,keyasint,omitempty"`
	// PinUVAuth is the first 16 bytes of HMAC-SHA-256 of clientDataHash using
	// pinToken which platform got from the authenticator
	PinUVAuth []byte `cbor:"8,keyasint,omitempty"`
	// PinUVAuthProtocol is the PIN protocol version chosen by the client
	PinUVAuthProtocol PinUVAuthProtocolVersion `cbor:"9,keyasint,omitempty"`
}

// MakeCredentialResponse
// TODO: structure may be different with different kind of attestations.
type MakeCredentialResponse struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData AuthData               `cbor:"2,keyasint"`
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

type GetAssertionRequest struct {
	RPID              string                   `cbor:"1,keyasint"`
	ClientDataHash    []byte                   `cbor:"2,keyasint"`
	AllowList         []*CredentialDescriptor  `cbor:"3,keyasint,omitempty"`
	Extensions        AuthenticatorExtensions  `cbor:"4,keyasint,omitempty"`
	Options           AuthenticatorOptions     `cbor:"5,keyasint,omitempty"`
	PinUVAuth         []byte                   `cbor:"6,keyasint,omitempty"`
	PinUVAuthProtocol PinUVAuthProtocolVersion `cbor:"7,keyasint,omitempty"`
}
type GetAssertionResponse struct {
	Credential          *CredentialDescriptor `cbor:"1,keyasint,omitempty"`
	AuthData            AuthData              `cbor:"2,keyasint"`
	Signature           []byte                `cbor:"3,keyasint"`
	User                *CredentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int                   `cbor:"5,keyasint,omitempty"`
	UserSelected        bool                  `cbor:"6,keyasint,omitempty"`
}

func (t *Token) GetAssertion(req *GetAssertionRequest) (*GetAssertionResponse, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	reqData, err := enc.Marshal(req)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(reqData)+1)
	data = append(data, cmdGetAssertion)
	data = append(data, reqData...)

	resp, err := t.d.CBOR(data)
	if err != nil {
		return nil, err
	}

	respData := &GetAssertionResponse{}
	if err := unmarshal(resp, respData); err != nil {
		return nil, err
	}

	return respData, nil
}

type GetNextAssertionRequest struct{}
type GetNextAssertionResponse struct{}

func (t *Token) GetNextAssertion(*GetNextAssertionRequest) (*GetNextAssertionResponse, error) {
	// TODO
	return nil, nil
}

type GetInfoResponse struct {
	Versions    []string             `cbor:"1,keyasint"`
	Extensions  []string             `cbor:"2,keyasint,omitempty"`
	AAGUID      []byte               `cbor:"3,keyasint"`
	Options     AuthenticatorOptions `cbor:"4,keyasint,omitempty"`
	MaxMsgSize  uint                 `cbor:"5,keyasint,omitempty"`
	PinProtocol []uint               `cbor:"6,keyasint,omitempty"`
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
	PinProtocol  PinUVAuthProtocolVersion `cbor:"1,keyasint"`
	SubCommand   ClientPinSubCommand      `cbor:"2,keyasint"`
	KeyAgreement *COSEKey                 `cbor:"3,keyasint,omitempty"`
	PinAuth      []byte                   `cbor:"4,keyasint,omitempty"`
	NewPinEnc    []byte                   `cbor:"5,keyasint,omitempty"`
	PinHashEnc   []byte                   `cbor:"6,keyasint,omitempty"`
}

type ClientPINResponse struct {
	KeyAgreement    *COSEKey `cbor:"1,keyasint,omitempty"`
	PinToken        []byte   `cbor:"2,keyasint,omitempty"`
	Retries         uint     `cbor:"3,keyasint,omitempty"`
	PowerCycleState bool     `cbor:"4,keyasint,omitempty"`
	UVRetries       uint     `cbor:"5,keyasint,omitempty"`
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

// Reset restore an authenticator back to a factory default state. User presence is required.
// In case of authenticators with no display, Reset request MUST have come to the authenticator within 10 seconds
// of powering up of the authenticator
// see: https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorReset
func (t *Token) Reset() error {
	resp, err := t.d.CBOR([]byte{cmdReset})
	if err != nil {
		return err
	}

	return checkResponse(resp)
}

func checkResponse(resp []byte) error {
	if len(resp) == 0 {
		return errors.New("ctap2token: empty response")
	}

	if resp[0] != statusSuccess {
		status, ok := ctap2Status[resp[0]]
		if !ok {
			status = fmt.Sprintf("unknown error %x", resp[0])
		}
		return fmt.Errorf("ctap2token: CBOR error: %s", status)
	}
	return nil
}

func unmarshal(resp []byte, out interface{}) error {
	if err := checkResponse(resp); err != nil {
		return err
	}

	if err := cbor.Unmarshal(resp[1:], out); err != nil {
		return err
	}

	return nil
}

// ClientDataHash is the hash of the ClientData contextual binding specified by host.
type ClientDataHash []byte

// CredentialRpEntity describes a Relying Party with which
// the new public key credential will be associated.
type CredentialRpEntity struct {
	// ID is a valid domain string that identifies the WebAuthn Relying Party.
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

type AuthData []byte

const authDataMinLength = 37

func (a AuthData) Parse() (*ParsedAuthData, error) {
	if len(a) < authDataMinLength {
		return nil, errors.New("ctap2token: invalid authData")
	}

	out := &ParsedAuthData{
		RPIDHash: a[:32],
		Flags: AuthDataFlag{
			UserPresent:            (a[32]&authDataFlagUP == authDataFlagUP),
			UserVerified:           (a[32]&authDataFlagUV == authDataFlagUV),
			AttestedCredentialData: (a[32]&authDataFlagAT == authDataFlagAT),
			HasExtensions:          (a[32]&authDataFlagED == authDataFlagED),
		},
		SignCount: binary.BigEndian.Uint32(a[33:authDataMinLength]),
	}

	if out.Flags.AttestedCredentialData {
		if len(a) <= authDataMinLength {
			return nil, errors.New("ctap2token: missing attestedCredentialData")
		}

		out.AttestedCredentialData = &AttestedCredentialData{
			AAGUID: a[authDataMinLength:53],
		}

		credIDLen := binary.BigEndian.Uint16(a[53:55])
		out.AttestedCredentialData.CredentialID = a[55 : 55+credIDLen]

		// a[55+credIDLen:] may contains the COSEKey + extensions map
		// but the decoder will only read the key and silently drop extensions data.
		out.AttestedCredentialData.CredentialPublicKey = &COSEKey{}
		if err := cbor.Unmarshal(a[55+credIDLen:], out.AttestedCredentialData.CredentialPublicKey); err != nil {
			return nil, err
		}
	}

	if out.Flags.HasExtensions {
		// When extensions are available, we must find out where the map start in the cbor data.
		// It can either be at a[authDataMinLength:] when out.Flags.AttestedCredentialData is false,
		// or at a[(authDataMinLength+16+2+credIDLen+COSEKeyLen):] when out.Flags.AttestedCredentialData is true
		// in this case, it requires to cbor-encode back the key to find its length.
		startIndex := authDataMinLength

		if out.Flags.AttestedCredentialData {
			em, err := cbor.CTAP2EncOptions().EncMode()
			if err != nil {
				return nil, err
			}
			pubkeyBytes, err := em.Marshal(out.AttestedCredentialData.CredentialPublicKey)
			if err != nil {
				return nil, err
			}
			startIndex += 16 + 2 + len(out.AttestedCredentialData.CredentialID) + len(pubkeyBytes)
		}

		if len(a) <= startIndex {
			return nil, errors.New("ctap2token: missing extensions")
		}

		out.Extensions = make(AuthenticatorExtensions)
		if err := cbor.Unmarshal(a[startIndex:], &out.Extensions); err != nil {
			return nil, err
		}
	}

	return out, nil
}

type ParsedAuthData struct {
	RPIDHash               []byte // 32 bytes Sha256 RP ID Hash
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             AuthenticatorExtensions
}

const (
	authDataFlagUP = 1 << iota
	authDataFlagReserved1
	authDataFlagUV
	authDataFlagReserved2
	authDataFlagReserved3
	authDataFlagReserved4
	authDataFlagAT
	authDataFlagED
)

type AuthDataFlag struct {
	UserPresent            bool
	UserVerified           bool
	AttestedCredentialData bool
	HasExtensions          bool
}

type AttestedCredentialData struct {
	AAGUID              []byte // 16 bytes ID for the authenticator
	CredentialID        []byte
	CredentialPublicKey *COSEKey
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

type AuthenticatorExtensions map[string]interface{}

type AuthenticatorOptions map[string]bool

type PinUVAuthProtocolVersion uint

const (
	PinProtoV1 PinUVAuthProtocolVersion = 1
)

type ClientPinSubCommand uint

const (
	GetPINRetries             ClientPinSubCommand = 0x01
	GetKeyAgreement           ClientPinSubCommand = 0x02
	SetPIN                    ClientPinSubCommand = 0x03
	ChangePIN                 ClientPinSubCommand = 0x04
	GetPINUvAuthTokenUsingPIN ClientPinSubCommand = 0x05
	GetPINUvAuthTokenUsingUv  ClientPinSubCommand = 0x06
	GetUVRetries              ClientPinSubCommand = 0x07
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
