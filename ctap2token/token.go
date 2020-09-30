package ctap2token

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/u2f/crypto"
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

var (
	ErrInvalidCommand       = errors.New("CTAP1_ERR_INVALID_COMMAND")
	ErrInvalidParameter     = errors.New("CTAP1_ERR_INVALID_PARAMETER")
	ErrInvalidLength        = errors.New("CTAP1_ERR_INVALID_LENGTH")
	ErrInvalidSeq           = errors.New("CTAP1_ERR_INVALID_SEQ")
	ErrTimeout              = errors.New("CTAP1_ERR_TIMEOUT")
	ErrChannelBusy          = errors.New("CTAP1_ERR_CHANNEL_BUSY")
	ErrLockRequired         = errors.New("CTAP1_ERR_LOCK_REQUIRED")
	ErrInvalidChannel       = errors.New("CTAP1_ERR_INVALID_CHANNEL")
	ErrCborUnexpectedType   = errors.New("CTAP2_ERR_CBOR_UNEXPECTED_TYPE")
	ErrInvalidCbor          = errors.New("CTAP2_ERR_INVALID_CBOR")
	ErrMissingParameter     = errors.New("CTAP2_ERR_MISSING_PARAMETER")
	ErrLimitExceeded        = errors.New("CTAP2_ERR_LIMIT_EXCEEDED")
	ErrUnsupportedExtension = errors.New("CTAP2_ERR_UNSUPPORTED_EXTENSION")
	ErrCredentialExcluded   = errors.New("CTAP2_ERR_CREDENTIAL_EXCLUDED")
	ErrProcessing           = errors.New("CTAP2_ERR_PROCESSING")
	ErrInvalidCredential    = errors.New("CTAP2_ERR_INVALID_CREDENTIAL")
	ErrUserActionPending    = errors.New("CTAP2_ERR_USER_ACTION_PENDING")
	ErrOperationPending     = errors.New("CTAP2_ERR_OPERATION_PENDING")
	ErrNoOperations         = errors.New("CTAP2_ERR_NO_OPERATIONS")
	ErrUnsupportedAlgorithm = errors.New("CTAP2_ERR_UNSUPPORTED_ALGORITHM")
	ErrOperationDenied      = errors.New("CTAP2_ERR_OPERATION_DENIED")
	ErrKeyStoreFull         = errors.New("CTAP2_ERR_KEY_STORE_FULL")
	ErrNoOperationPending   = errors.New("CTAP2_ERR_NO_OPERATION_PENDING")
	ErrUnsupportedOption    = errors.New("CTAP2_ERR_UNSUPPORTED_OPTION")
	ErrInvalidOption        = errors.New("CTAP2_ERR_INVALID_OPTION")
	ErrKeepaliveCancel      = errors.New("CTAP2_ERR_KEEPALIVE_CANCEL")
	ErrNoCredentials        = errors.New("CTAP2_ERR_NO_CREDENTIALS")
	ErrUserActionTimeout    = errors.New("CTAP2_ERR_USER_ACTION_TIMEOUT")
	ErrNotAllowed           = errors.New("CTAP2_ERR_NOT_ALLOWED")
	ErrPinInvalid           = errors.New("CTAP2_ERR_PIN_INVALID")
	ErrPinBlocked           = errors.New("CTAP2_ERR_PIN_BLOCKED")
	ErrPinAuthInvalid       = errors.New("CTAP2_ERR_PIN_AUTH_INVALID")
	ErrPinAuthBlocked       = errors.New("CTAP2_ERR_PIN_AUTH_BLOCKED")
	ErrPinNotSet            = errors.New("CTAP2_ERR_PIN_NOT_SET")
	ErrPinRequired          = errors.New("CTAP2_ERR_PIN_REQUIRED")
	ErrPinPolicyViolation   = errors.New("CTAP2_ERR_PIN_POLICY_VIOLATION")
	ErrPinTokenExpired      = errors.New("CTAP2_ERR_PIN_TOKEN_EXPIRED")
	ErrRequestTooLarge      = errors.New("CTAP2_ERR_REQUEST_TOO_LARGE")
	ErrActionTimeout        = errors.New("CTAP2_ERR_ACTION_TIMEOUT")
	ErrUpRequired           = errors.New("CTAP2_ERR_UP_REQUIRED")
	ErrSpecLast             = errors.New("CTAP2_ERR_SPEC_LAST")
	ErrExtensionFirst       = errors.New("CTAP2_ERR_EXTENSION_FIRST")
	ErrExtensionLast        = errors.New("CTAP2_ERR_EXTENSION_LAST")
	ErrVendorFirst          = errors.New("CTAP2_ERR_VENDOR_FIRST")
	ErrVendorLast           = errors.New("CTAP2_ERR_VENDOR_LAST")
)

// CTAP2 error status from https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#error-responses
var ctapErrors = map[byte]error{
	0x01: ErrInvalidCommand,
	0x02: ErrInvalidParameter,
	0x03: ErrInvalidLength,
	0x04: ErrInvalidSeq,
	0x05: ErrTimeout,
	0x06: ErrChannelBusy,
	0x0A: ErrLockRequired,
	0x0B: ErrInvalidChannel,
	0x11: ErrCborUnexpectedType,
	0x12: ErrInvalidCbor,
	0x14: ErrMissingParameter,
	0x15: ErrLimitExceeded,
	0x16: ErrUnsupportedExtension,
	0x19: ErrCredentialExcluded,
	0x21: ErrProcessing,
	0x22: ErrInvalidCredential,
	0x23: ErrUserActionPending,
	0x24: ErrOperationPending,
	0x25: ErrNoOperations,
	0x26: ErrUnsupportedAlgorithm,
	0x27: ErrOperationDenied,
	0x28: ErrKeyStoreFull,
	0x2A: ErrNoOperationPending,
	0x2B: ErrUnsupportedOption,
	0x2C: ErrInvalidOption,
	0x2D: ErrKeepaliveCancel,
	0x2E: ErrNoCredentials,
	0x2F: ErrUserActionTimeout,
	0x30: ErrNotAllowed,
	0x31: ErrPinInvalid,
	0x32: ErrPinBlocked,
	0x33: ErrPinAuthInvalid,
	0x34: ErrPinAuthBlocked,
	0x35: ErrPinNotSet,
	0x36: ErrPinRequired,
	0x37: ErrPinPolicyViolation,
	0x38: ErrPinTokenExpired,
	0x39: ErrRequestTooLarge,
	0x3A: ErrActionTimeout,
	0x3B: ErrUpRequired,
	0xDF: ErrSpecLast,
	0xE0: ErrExtensionFirst,
	0xEF: ErrExtensionLast,
	0xF0: ErrVendorFirst,
	0xFF: ErrVendorLast,
}

type Device interface {
	// CBOR sends a CTAP2 CBOR encoded message to the device and returns the response.
	CBOR(data []byte) ([]byte, error)
	// Message sends a CTAP1 message to the device and returns the response.
	Message(data []byte) ([]byte, error)
	// SetResponseTimeout allow to control the maximum time to wait for the device response
	SetResponseTimeout(timeout time.Duration)
	Cancel()
	Close()
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
	// we need a pointer here to distinguish nil pinUVAuth from empty.
	// When nil, it must be omitted from the CBOR encoded request, but included when empty,
	PinUVAuth *[]byte `cbor:"8,keyasint,omitempty"`
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
	PinUVAuth         PinUVAuth                `cbor:"6,keyasint,omitempty"`
	PinUVAuthProtocol PinUVAuthProtocolVersion `cbor:"7,keyasint,omitempty"`
}

type AssertionResponse struct {
	Credential          *CredentialDescriptor `cbor:"1,keyasint,omitempty"`
	AuthData            AuthData              `cbor:"2,keyasint"`
	Signature           []byte                `cbor:"3,keyasint"`
	User                *CredentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int                   `cbor:"5,keyasint,omitempty"`
	UserSelected        bool                  `cbor:"6,keyasint,omitempty"`
}

func (t *Token) GetAssertion(req *GetAssertionRequest) (*AssertionResponse, error) {
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

	respData := &AssertionResponse{}
	if err := unmarshal(resp, respData); err != nil {
		return nil, err
	}

	return respData, nil
}

// GetNextAssertion is used to obtain the next per-credential signature for a given GetAssertion request,
// when GetAssertion.NumberOfCredentials is greater than 1.
// see https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorGetNextAssertion
func (t *Token) GetNextAssertion() (*AssertionResponse, error) {
	resp, err := t.d.CBOR([]byte{cmdGetNextAssertion})
	if err != nil {
		return nil, err
	}

	respData := &AssertionResponse{}
	if err := unmarshal(resp, respData); err != nil {
		return nil, err
	}
	return respData, nil
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
	KeyAgreement *crypto.COSEKey          `cbor:"3,keyasint,omitempty"`
	PinAuth      []byte                   `cbor:"4,keyasint,omitempty"`
	NewPinEnc    []byte                   `cbor:"5,keyasint,omitempty"`
	PinHashEnc   []byte                   `cbor:"6,keyasint,omitempty"`
}

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

type ClientPINResponse struct {
	KeyAgreement    *crypto.COSEKey `cbor:"1,keyasint,omitempty"`
	PinToken        []byte          `cbor:"2,keyasint,omitempty"`
	Retries         uint            `cbor:"3,keyasint,omitempty"`
	PowerCycleState bool            `cbor:"4,keyasint,omitempty"`
	UVRetries       uint            `cbor:"5,keyasint,omitempty"`
}

func (t *Token) ClientPIN(req *ClientPINRequest) (*ClientPINResponse, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	reqData, err := enc.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("ctap2token: failed to marshal request: %w", err)
	}

	data := make([]byte, 0, len(reqData)+1)
	data = append(data, cmdClientPIN)
	data = append(data, reqData...)

	resp, err := t.d.CBOR(data)
	if err != nil {
		return nil, fmt.Errorf("ctap2token: cbor failed: %w", err)
	}

	respData := &ClientPINResponse{}
	if err := unmarshal(resp, respData); err != nil {
		return nil, fmt.Errorf("ctap2token: failed to unmarshal response: %w", err)
	}

	return respData, nil
}

func (t *Token) AuthenticatorSelection(ctx context.Context) error {
	dummyHash := make([]byte, sha256.Size)
	_, err := t.MakeCredential(&MakeCredentialRequest{
		ClientDataHash: dummyHash,
		User: CredentialUserEntity{
			ID:   []byte{0x1},
			Name: "dummy",
		},
		RP: CredentialRpEntity{
			ID: ".dummy",
		},
		PubKeyCredParams: []CredentialParam{
			PublicKeyES256,
		},
		PinUVAuth:         &[]byte{},
		PinUVAuthProtocol: PinProtoV1,
	})

	switch errors.Unwrap(err) {
	case nil, ErrPinAuthInvalid, ErrPinNotSet:
		return nil
	default:
		return err
	}
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

func (t *Token) SetResponseTimeout(timeout time.Duration) {
	t.d.SetResponseTimeout(timeout)
}

func (t *Token) Cancel() {
	t.d.Cancel()
}

func (t *Token) Close() {
	t.d.Close()
}

func checkResponse(resp []byte) error {
	if len(resp) == 0 {
		return errors.New("ctap2token: empty response")
	}

	if resp[0] != statusSuccess {
		status, ok := ctapErrors[resp[0]]
		if !ok {
			status = fmt.Errorf("unknown error %x", resp[0])
		}
		return fmt.Errorf("ctap2token: CBOR error: %w", status)
	}
	return nil
}

func unmarshal(resp []byte, out interface{}) error {
	if err := checkResponse(resp); err != nil {
		return err
	}

	if len(resp) == 1 {
		return nil
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

func (u *CredentialUserEntity) Bytes() ([]byte, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	return enc.Marshal(u)
}

type AuthData []byte

const authDataMinLength = 37

func (a AuthData) Parse() (*ParsedAuthData, error) {
	if len(a) < authDataMinLength {
		return nil, fmt.Errorf("ctap2token: authData too short, got %d bytes, want at least %d", len(a), authDataMinLength)
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
		out.AttestedCredentialData.CredentialPublicKey = &crypto.COSEKey{}
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

func (p *ParsedAuthData) Bytes() ([]byte, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, authDataMinLength)
	out = append(out, p.RPIDHash...)

	var flag byte
	if p.Flags.UserPresent {
		flag |= authDataFlagUP
	}
	if p.Flags.UserVerified {
		flag |= authDataFlagUV
	}
	if p.Flags.AttestedCredentialData {
		flag |= authDataFlagAT
	}
	if p.Flags.HasExtensions {
		flag |= authDataFlagED
	}
	out = append(out, flag)

	signCount := make([]byte, 4)
	binary.BigEndian.PutUint32(signCount, p.SignCount)
	out = append(out, signCount...)

	if p.Flags.AttestedCredentialData {
		out = append(out, p.AttestedCredentialData.AAGUID...)

		credIDLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credIDLen, uint16(len(p.AttestedCredentialData.CredentialID)))

		out = append(out, credIDLen...)
		out = append(out, p.AttestedCredentialData.CredentialID...)

		pubkey, err := enc.Marshal(p.AttestedCredentialData.CredentialPublicKey)
		if err != nil {
			return nil, err
		}

		out = append(out, pubkey...)
	}

	if p.Flags.HasExtensions {
		exts, err := enc.Marshal(p.Extensions)
		if err != nil {
			return nil, err
		}
		out = append(out, exts...)
	}

	return out, nil
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
	CredentialPublicKey *crypto.COSEKey
}

type CredentialParam struct {
	Type CredentialType `cbor:"type"`
	Alg  crypto.Alg     `cbor:"alg"`
}

var (
	PublicKeyRS256 CredentialParam = CredentialParam{Type: PublicKey, Alg: crypto.RS256}
	PublicKeyPS256 CredentialParam = CredentialParam{Type: PublicKey, Alg: crypto.PS256}
	PublicKeyES256 CredentialParam = CredentialParam{Type: PublicKey, Alg: crypto.ES256}
)

// CredentialType defines the type of credential, as defined in https://www.w3.org/TR/webauthn/#credentialType
type CredentialType string

const (
	PublicKey CredentialType = "public-key"
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

type PinUVAuth []byte

type PinUVAuthProtocolVersion uint

const (
	PinProtoV1 PinUVAuthProtocolVersion = 1
)
