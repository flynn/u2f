package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"

	"github.com/flynn/u2f/ctap2token"
	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/u2ftoken"
)

type WebauthnToken interface {
	// Register is the equivalent to navigator.credential.create()
	Register(origin string, req *RegisterRequest) (*RegisterResponse, error)
	// Authenticate is the equivalent to navigator.credential.get()
	Authenticate(req *AuthenticateRequest) (*AuthenticateResponse, error)
}

type RegisterRequest struct {
	PublicKey struct {
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
		ExcludeCredentials []struct {
			Type       string   `json:"type"`
			ID         []byte   `json:"id"`
			Transports []string `json:"transports"`
		} `json:"excludeCredentials"`
		AuthenticatorSelection struct {
			AuthenticatorAttachment string `json:"authenticatorAttachment"`
			RequireResidentKey      bool   `json:"requireResidentKey"`
			UserVerification        string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		Timeout     int                    `json:"timeout"`
		Extensions  map[string]interface{} `json:"extensions"`
		Attestation string                 `json:"attestation"`
	} `json:"publicKey"`
}

type RegisterResponse struct {
	ID       string              `json:"id"`
	RawID    URLEncodedBase64    `json:"rawId"`
	Type     string              `json:"type"`
	Response AttestationResponse `json:"response"`
}

type AttestationResponse struct {
	AttestationObject URLEncodedBase64 `json:"attestationObject"`
	ClientDataJSON    URLEncodedBase64 `json:"clientDataJSON"`
}

type AuthenticateRequest struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		Timeout          int    `json:"timeout"`
		RpID             string `json:"rpId"`
		AllowCredentials []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"allowCredentials"`
		Extensions struct {
			TxAuthSimple string `json:"txAuthSimple"`
		} `json:"extensions"`
	} `json:"publicKey"`
}
type AuthenticateResponse struct {
	ID       string            `json:"id"`
	RawID    []byte            `json:"rawId"`
	Type     string            `json:"type"`
	Response AssertionResponse `json:"response"`
}

type AssertionResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle"`
}

type ctap2TWebauthnToken struct {
	t          *ctap2.Token
	pinHandler pin.PINHandler
}

type ctap1WebauthnToken struct {
	t *u2ftoken.Token
}

type Device interface {
	ctap2.Device
	u2ftoken.Device
}

type collectedClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	// TODO tokenBinding ?
}

// NewToken returns a new WebAuthn capable token.
// It will first try to communicate with the device using FIDO2 / CTAP2 protocol,
// and fallback using U2F / CTAP1 on failure.
// A pinHandler is required when using a CTAP2 compatible authenticator with a configured PIN, when requests
// require user verification.
func NewToken(d Device, pinHandler pin.PINHandler) (WebauthnToken, error) {
	t := ctap2.NewToken(d)
	if _, err := t.GetInfo(); err != nil {
		return &ctap1WebauthnToken{
			t: u2ftoken.NewToken(d),
		}, nil
	}
	return &ctap2TWebauthnToken{
		t:          t,
		pinHandler: pinHandler,
	}, nil
}

var emptyAAGUID = make([]byte, 16)

/*
TODO List
	- handle custom timeout
	- extensions support
	- what is collectedClientData.tokenBinding (https://www.w3.org/TR/webauthn/#dom-collectedclientdata-tokenbinding)
	- Handle multiple authenticator / multiple transports
*/

var supportedCredentialTypes = map[string]ctap2.CredentialType{
	string(ctap2.PublicKey): ctap2.PublicKey,
}
var supportedTransports = map[string]ctap2.AuthenticatorTransport{
	string(ctap2.USB): ctap2.USB,
}

func (w *ctap2TWebauthnToken) Register(origin string, req *RegisterRequest) (*RegisterResponse, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid origin: %w", err)
	}
	if originURL.Opaque != "" {
		return nil, fmt.Errorf("webauthn: invalid opaque origin %q", origin)
	}

	effectiveDomain := originURL.Hostname() // TODO validate with https://url.spec.whatwg.org/#valid-domain

	rpID := req.PublicKey.Rp.ID
	if rpID == "" {
		rpID = effectiveDomain
	}

	credTypesAndPubKeyAlgs := make([]ctap2.CredentialParam, 0, len(req.PublicKey.PubKeyCredParams))
	for _, cp := range req.PublicKey.PubKeyCredParams {
		t, ok := supportedCredentialTypes[cp.Type]
		if !ok {
			continue
		}

		credTypesAndPubKeyAlgs = append(credTypesAndPubKeyAlgs, ctap2.CredentialParam{
			Type: t,
			Alg:  ctap2.Alg(cp.Alg),
		})
	}

	if len(credTypesAndPubKeyAlgs) == 0 && len(req.PublicKey.PubKeyCredParams) > 0 {
		return nil, errors.New("webauthn: credential parameters not supported")
	}

	// TODO add support for extensions (bullet point 11 and 12 from https://www.w3.org/TR/webauthn/#createCredential)
	clientExtensions := make(map[string]interface{})

	clientData := collectedClientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(req.PublicKey.Challenge),
		Origin:    fmt.Sprintf("%s://%s", originURL.Scheme, originURL.Host),
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, err
	}

	sha := sha256.New()
	if _, err := sha.Write(clientDataJSON); err != nil {
		return nil, err
	}
	clientDataHash := sha.Sum(nil)

	excludeList := make([]ctap2.CredentialDescriptor, 0, len(req.PublicKey.ExcludeCredentials))
	for _, c := range req.PublicKey.ExcludeCredentials {
		t, ok := supportedCredentialTypes[c.Type]
		if !ok {
			return nil, fmt.Errorf("webauthn: unsupported excluded credential type %q", c.Type)
		}

		transports := make([]ctap2.AuthenticatorTransport, 0, len(c.Transports))
		for _, transport := range c.Transports {
			ctapTransport, ok := supportedTransports[transport]
			if !ok {
				return nil, fmt.Errorf("webauthn: unsupported transport type %q", transport)
			}
			transports = append(transports, ctapTransport)
		}

		excludeList = append(excludeList, ctap2.CredentialDescriptor{
			ID:         c.ID,
			Transports: transports,
			Type:       t,
		})
	}

	options := make(ctap2.AuthenticatorOptions)
	if req.PublicKey.AuthenticatorSelection.RequireResidentKey {
		options["rk"] = true
	}

	var pinProtocol ctap2.PinUVAuthProtocolVersion
	var pinUVAuth []byte
	switch req.PublicKey.AuthenticatorSelection.UserVerification {
	case "discouraged":
		// Do nothing
	case "required":
		pinProtocol = ctap2.PinProtoV1
		pinUVAuth, err = w.pinHandler.Execute(clientDataHash)
		if err != nil {
			return nil, err
		}
	case "preferred":
		infos, err := w.t.GetInfo()
		if err != nil {
			return nil, err
		}

		// Most authenticators seems to set clientPin option to true when the PIN is set
		// TODO: validate this is a standard way to do that
		if pin, ok := infos.Options["clientPin"]; ok && pin {
			pinProtocol = ctap2.PinProtoV1
			pinUVAuth, err = w.pinHandler.Execute(clientDataHash)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("unsupported user verification option %q", req.PublicKey.AuthenticatorSelection.UserVerification)
	}

	resp, err := w.t.MakeCredential(&ctap2.MakeCredentialRequest{
		ClientDataHash: clientDataHash,
		RP: ctap2.CredentialRpEntity{
			ID:   rpID,
			Name: req.PublicKey.Rp.Name,
			Icon: req.PublicKey.Rp.Icon,
		},
		User: ctap2token.CredentialUserEntity{
			ID:          req.PublicKey.User.ID,
			Icon:        req.PublicKey.User.Icon,
			Name:        req.PublicKey.User.Name,
			DisplayName: req.PublicKey.User.DisplayName,
		},
		PubKeyCredParams:  credTypesAndPubKeyAlgs,
		ExcludeList:       excludeList,
		Extensions:        clientExtensions,
		Options:           options,
		PinUVAuth:         pinUVAuth,
		PinUVAuthProtocol: pinProtocol,
	})
	if err != nil {
		return nil, err
	}

	authData, err := resp.AuthData.Parse()
	if err != nil {
		return nil, err
	}

	switch req.PublicKey.Attestation {
	case "none":
		isEmptyAAGUID := bytes.Equal(authData.AttestedCredentialData.AAGUID, emptyAAGUID)
		_, x5c := resp.AttSmt["x5c"]
		_, ecdaaKeyId := resp.AttSmt["ecdaaKeyId"]
		if resp.Fmt == "packed" && isEmptyAAGUID && !x5c && !ecdaaKeyId {
			break // self attestation is being used and no further action is needed.
		}

		authData.AttestedCredentialData.AAGUID = emptyAAGUID
		d, err := authData.Bytes()
		if err != nil {
			return nil, err
		}

		resp = &ctap2.MakeCredentialResponse{
			Fmt:      "none",
			AuthData: d,
			AttSmt:   make(map[string]interface{}),
		}
	case "indirect":
		// TODO
	case "direct":
		// Do nothing
	default:
		return nil, fmt.Errorf("unsupported attestation mode %q", req.PublicKey.Attestation)
	}

	attestationObject, err := resp.AttestationObject()
	if err != nil {
		return nil, err
	}

	return &RegisterResponse{
		ID:    base64.RawURLEncoding.EncodeToString(authData.AttestedCredentialData.CredentialID),
		RawID: authData.AttestedCredentialData.CredentialID,
		Type:  "public-key",
		Response: AttestationResponse{
			ClientDataJSON:    clientDataJSON,
			AttestationObject: attestationObject,
		},
	}, nil
}
func (w *ctap2TWebauthnToken) Authenticate(req *AuthenticateRequest) (*AuthenticateResponse, error) {
	panic("not implemented yet")
	return nil, nil
}

func (w *ctap1WebauthnToken) Register(origin string, req *RegisterRequest) (*RegisterResponse, error) {
	panic("not implemented yet")
	return nil, nil
}
func (w *ctap1WebauthnToken) Authenticate(req *AuthenticateRequest) (*AuthenticateResponse, error) {
	panic("not implemented yet")
	return nil, nil
}

// URLEncodedBase64 represents a byte slice holding URL-encoded base64 data.
// When fields of this type are unmarshaled from JSON, the data is base64
// decoded into a byte slice.
type URLEncodedBase64 []byte

// UnmarshalJSON base64 decodes a URL-encoded value, storing the result in the
// provided byte slice.
func (dest *URLEncodedBase64) UnmarshalJSON(data []byte) error {
	// Trim the leading spaces
	data = bytes.Trim(data, "\"")
	out := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(out, data)
	if err != nil {
		return err
	}

	v := reflect.ValueOf(dest).Elem()
	v.SetBytes(out[:n])
	return nil
}

// MarshalJSON base64 encodes a non URL-encoded value, storing the result in the
// provided byte slice.
func (data URLEncodedBase64) MarshalJSON() ([]byte, error) {
	if data == nil {
		return []byte("null"), nil
	}
	return []byte(`"` + base64.RawURLEncoding.EncodeToString(data) + `"`), nil
}
