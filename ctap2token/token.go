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

type MakeCredentialRequest struct{}
type MakeCredentialResponse struct{}

func (t *Token) MakeCredential(req *MakeCredentialRequest) (*MakeCredentialResponse, error) {
	return nil, nil
}

type GetAssertionRequest struct{}
type GetAssertioNResponse struct{}

func (t *Token) GetAssertion(req *GetAssertionRequest) (*GetAssertioNResponse, error) {
	return nil, nil
}

type GetInfoResponse struct {
	Versions    []string        `cbor:"1,keyasint,toarray"`
	Extensions  []string        `cbor:"2,keyasint,toarray"`
	AAGUID      []byte          `cbor:"3,keyasint"`
	Options     map[string]bool `cbor:"4,keyasint"`
	MaxMsgSize  uint            `cbor:"5,keyasint"`
	PinProtocol []uint          `cbor:"6,keyasint,toarray"`
}

func (t *Token) GetInfo() (*GetInfoResponse, error) {
	resp, err := t.d.CBOR([]byte{cmdGetInfo})
	if err != nil {
		return nil, err
	}

	infos := &GetInfoResponse{}
	if err := cbor.Unmarshal(resp[1:], &infos); err != nil {
		return nil, err
	}
	return infos, nil
}

type ClientPINRequest struct{}
type ClientPINResponse struct{}

func (t *Token) ClientPIN(req *ClientPINRequest) (*ClientPINResponse, error) {
	return nil, nil
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

func checkCBORResponse(resp []byte) ([]byte, error) {
	if len(resp) == 0 || resp[0] != statusSuccess {
		status, ok := ctap2Status[resp[0]]
		if !ok {
			status = fmt.Sprintf("unknown error %x", resp[0])
		}
		return nil, fmt.Errorf("ctap2token: CBOR error: %s", status)
	}

	return resp[1:], nil
}
