package webauthn

import (
	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/u2ftoken"
	"github.com/fxamacker/cbor/v2"
)

type Token interface {
	// Register is the equivalent to navigator.credential.create()
	Register(origin string, req *RegisterRequest) (*RegisterResponse, error)
	// Authenticate is the equivalent to navigator.credential.get()
	Authenticate(origin string, req *AuthenticateRequest) (*AuthenticateResponse, error)
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
	Challenge []byte `json:"challenge"`
	Rp        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Icon string `json:"icon"`
	} `json:"rp"`
	User struct {
		ID          []byte `json:"id"`
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
		Icon        string `json:"icon"`
	} `json:"user"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`
	ExcludeCredentials     []ExcludedCredential `json:"excludeCredentials"`
	AuthenticatorSelection struct {
		AuthenticatorAttachment string `json:"authenticatorAttachment"`
		RequireResidentKey      bool   `json:"requireResidentKey"`
		UserVerification        string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	Timeout     int                    `json:"timeout"`
	Extensions  map[string]interface{} `json:"extensions"`
	Attestation string                 `json:"attestation"`
}

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
	UserVerification string                 `json:"userVerification"`
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

type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	// TODO tokenBinding ?
}
