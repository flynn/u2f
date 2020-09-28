package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/u2f/crypto"
	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
)

var supportedCTAP2CredentialTypes = map[string]ctap2.CredentialType{
	string(ctap2.PublicKey): ctap2.PublicKey,
}
var supportedCTAP2Transports = map[string]ctap2.AuthenticatorTransport{
	string(ctap2.USB): ctap2.USB,
}

type ctap2WebauthnToken struct {
	t       *ctap2.Token
	options map[string]bool
}

func (w *ctap2WebauthnToken) Register(req *RegisterRequest, p *RequestParams) (*RegisterResponse, error) {
	credTypesAndPubKeyAlgs := make([]ctap2.CredentialParam, 0, len(req.PubKeyCredParams))
	for _, cp := range req.PubKeyCredParams {
		t, ok := supportedCTAP2CredentialTypes[cp.Type]
		if !ok {
			continue
		}

		credTypesAndPubKeyAlgs = append(credTypesAndPubKeyAlgs, ctap2.CredentialParam{
			Type: t,
			Alg:  crypto.Alg(cp.Alg),
		})
	}

	if len(credTypesAndPubKeyAlgs) == 0 && len(req.PubKeyCredParams) > 0 {
		return nil, errors.New("webauthn: credential parameters not supported")
	}

	// TODO add support for extensions (bullet point 11 and 12 from https://www.w3.org/TR/webauthn/#createCredential)
	clientExtensions := make(map[string]interface{})

	clientDataJSON, clientDataHash, err := p.ClientData.EncodeAndHash()
	if err != nil {
		return nil, err
	}

	excludeList := make([]ctap2.CredentialDescriptor, 0, len(req.ExcludeCredentials))
	for _, c := range req.ExcludeCredentials {
		t, ok := supportedCTAP2CredentialTypes[c.Type]
		if !ok {
			return nil, fmt.Errorf("webauthn: unsupported excluded credential type %q", c.Type)
		}

		transports := make([]ctap2.AuthenticatorTransport, 0, len(c.Transports))
		for _, transport := range c.Transports {
			ctapTransport, ok := supportedCTAP2Transports[transport]
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
	if req.AuthenticatorSelection.RequireResidentKey {
		options["rk"] = true
	}

	var pinProtocol ctap2.PinUVAuthProtocolVersion
	var pinUVAuth []byte
	if len(p.UserPIN) > 0 {
		var err error
		pinUVAuth, err = pin.ExchangeUserPinToPinAuth(w.t, p.UserPIN, clientDataHash)
		if err != nil {
			return nil, err
		}
		pinProtocol = ctap2.PinProtoV1
	}
	resp, err := w.t.MakeCredential(&ctap2.MakeCredentialRequest{
		ClientDataHash: clientDataHash,
		RP: ctap2.CredentialRpEntity{
			ID:   req.Rp.ID,
			Name: req.Rp.Name,
			Icon: req.Rp.Icon,
		},
		User: ctap2.CredentialUserEntity{
			ID:          req.User.ID,
			Icon:        req.User.Icon,
			Name:        req.User.Name,
			DisplayName: req.User.DisplayName,
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

	switch req.Attestation {
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
		return nil, fmt.Errorf("unsupported attestation mode %q", req.Attestation)
	}

	return &RegisterResponse{
		ID: authData.AttestedCredentialData.CredentialID,
		Response: AttestationResponse{
			ClientDataJSON: clientDataJSON,
			AttestationObject: AttestationObject{
				Fmt:      resp.Fmt,
				AuthData: resp.AuthData,
				AttSmt:   resp.AttSmt,
			},
		},
	}, nil
}

func (w *ctap2WebauthnToken) Authenticate(req *AuthenticateRequest, p *RequestParams) (*AuthenticateResponse, error) {
	// TODO add support for extensions (bullet point 8 from https://www.w3.org/TR/2020/WD-webauthn-2-20200730/#sctn-discover-from-external-source)
	clientExtensions := make(map[string]interface{})

	clientDataJSON, clientDataHash, err := p.ClientData.EncodeAndHash()
	if err != nil {
		return nil, err
	}

	var pinProtocol ctap2.PinUVAuthProtocolVersion
	var pinUVAuth []byte
	if len(p.UserPIN) > 0 {
		var err error
		pinUVAuth, err = pin.ExchangeUserPinToPinAuth(w.t, p.UserPIN, clientDataHash)
		if err != nil {
			return nil, err
		}
		pinProtocol = ctap2.PinProtoV1
	}

	allowList := make([]*ctap2.CredentialDescriptor, 0, len(req.AllowCredentials))
	for _, c := range req.AllowCredentials {
		t, ok := supportedCTAP2CredentialTypes[c.Type]
		if !ok {
			return nil, fmt.Errorf("webauthn: unsupported excluded credential type %q", c.Type)
		}

		allowList = append(allowList, &ctap2.CredentialDescriptor{
			ID:   c.ID,
			Type: t,
		})
	}

	resp, err := w.t.GetAssertion(&ctap2.GetAssertionRequest{
		RPID:              req.RpID,
		ClientDataHash:    clientDataHash,
		PinUVAuth:         pinUVAuth,
		PinUVAuthProtocol: pinProtocol,
		AllowList:         allowList,
		Extensions:        clientExtensions,
	})
	if err != nil {
		return nil, err
	}

	userHandle := []byte{}
	if resp.User != nil {
		var err error
		userHandle, err = resp.User.Bytes()
		if err != nil {
			return nil, err
		}
	}

	return &AuthenticateResponse{
		ID: resp.Credential.ID,
		Response: AssertionResponse{
			AuthenticatorData: resp.AuthData,
			Signature:         resp.Signature,
			ClientDataJSON:    clientDataJSON,
			UserHandle:        userHandle,
		},
	}, nil
}

func (w *ctap2WebauthnToken) AuthenticatorSelection(ctx context.Context) error {
	return w.t.AuthenticatorSelection(ctx)
}

func (w *ctap2WebauthnToken) Cancel() {
	w.t.Cancel()
}

func (w *ctap2WebauthnToken) RequireUV() bool {
	return w.options["clientPin"]
}

func (w *ctap2WebauthnToken) SupportRK() bool {
	return w.options["rk"]
}

func (w *ctap2WebauthnToken) SetResponseTimeout(timeout time.Duration) {
	w.t.SetResponseTimeout(timeout)
}
