package webauthn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/fxamacker/cbor/v2"
)

type Authenticator interface {
	// Register is the equivalent to navigator.credential.create()
	Register(ctx context.Context, req *RegisterRequest, p *RequestParams) (*RegisterResponse, error)
	// Authenticate is the equivalent to navigator.credential.get()
	Authenticate(ctx context.Context, req *AuthenticateRequest, p *RequestParams) (*AuthenticateResponse, error)

	AuthenticatorSelection(ctx context.Context) error

	SetResponseTimeout(timeout time.Duration)
	RequireUV() bool
	SupportRK() bool
	Close()
}

type RequestParams struct {
	UserPIN    []byte
	ClientData CollectedClientData
}

type Device interface {
	ctap2.Device
	u2ftoken.Device
}

type ExcludedCredential struct {
	Type       string   `json:"type"`
	ID         []byte   `json:"id"`
	Transports []string `json:"transports"`
}

type RegisterRequest struct {
	Challenge              []byte                 `json:"challenge"`
	RP                     RP                     `json:"rp"`
	User                   User                   `json:"user"`
	PubKeyCredParams       []PubKeyCredParams     `json:"pubKeyCredParams"`
	ExcludeCredentials     []ExcludedCredential   `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Timeout                int                    `json:"timeout"`
	Extensions             map[string]interface{} `json:"extensions"`
	Attestation            string                 `json:"attestation"`
}

type RP struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon string `json:"icon"`
}

type User struct {
	ID          []byte `json:"id"`
	DisplayName string `json:"displayName"`
	Name        string `json:"name"`
	Icon        string `json:"icon"`
}

type PubKeyCredParams struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string           `json:"authenticatorAttachment"`
	RequireResidentKey      bool             `json:"requireResidentKey"`
	UserVerification        UserVerification `json:"userVerification"`
}

type UserVerification string

const (
	UVDiscouraged UserVerification = "discouraged"
	UVPreferred   UserVerification = "preferred"
	UVRequired    UserVerification = "required"
)

type RegisterResponse struct {
	ID       []byte
	Response AttestationResponse
}

type AttestationResponse struct {
	AttestationObject AttestationObject
	ClientDataJSON    []byte
}

type AttestationObject struct {
	Fmt      string                 `cbor:"1,keyasint"`
	AuthData []byte                 `cbor:"2,keyasint"`
	AttSmt   map[string]interface{} `cbor:"3,keyasint"`
}

func (m AttestationObject) CBOREncode(keyAsInt bool) ([]byte, error) {
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		return nil, err
	}

	if !keyAsInt {
		att := make(map[string]interface{})
		att["fmt"] = m.Fmt
		att["attStmt"] = m.AttSmt
		att["authData"] = m.AuthData
		return enc.Marshal(att)
	}

	return enc.Marshal(m)
}

type AllowedCredential struct {
	Type string `json:"type"`
	ID   []byte `json:"id"`
}

type AuthenticateRequest struct {
	Challenge        []byte                 `json:"challenge"`
	Timeout          int                    `json:"timeout"`
	RpID             string                 `json:"rpId"`
	AllowCredentials []AllowedCredential    `json:"allowCredentials"`
	UserVerification UserVerification       `json:"userVerification"`
	Extensions       map[string]interface{} `json:"extensions"`
}
type AuthenticateResponse struct {
	ID       []byte
	Response AssertionResponse
}

type AssertionResponse struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	UserHandle        []byte
}

type CollectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func (c CollectedClientData) EncodeAndHash() (dataJSON []byte, dataHash []byte, err error) {
	dataJSON, err = json.Marshal(c)
	if err != nil {
		return nil, nil, err
	}

	hash := sha256.Sum256(dataJSON)
	dataHash = hash[:]
	return dataJSON, dataHash, nil
}
