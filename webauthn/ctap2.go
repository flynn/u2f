package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/flynn/u2f/crypto"
	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
)

type ctap2TWebauthnToken struct {
	t          *ctap2.Token
	pinHandler pin.PINHandler
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

	rpID := req.Rp.ID
	if rpID == "" {
		rpID = effectiveDomain
	}

	credTypesAndPubKeyAlgs := make([]ctap2.CredentialParam, 0, len(req.PubKeyCredParams))
	for _, cp := range req.PubKeyCredParams {
		t, ok := supportedCredentialTypes[cp.Type]
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

	clientData := collectedClientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(req.Challenge),
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

	excludeList := make([]ctap2.CredentialDescriptor, 0, len(req.ExcludeCredentials))
	for _, c := range req.ExcludeCredentials {
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
	if req.AuthenticatorSelection.RequireResidentKey {
		options["rk"] = true
	}

	pinUVAuth, pinProtocol, err := w.userVerification(req.AuthenticatorSelection.UserVerification, clientDataHash)
	if err != nil {
		return nil, err
	}

	resp, err := w.t.MakeCredential(&ctap2.MakeCredentialRequest{
		ClientDataHash: clientDataHash,
		RP: ctap2.CredentialRpEntity{
			ID:   rpID,
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

func (w *ctap2TWebauthnToken) Authenticate(origin string, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid origin: %w", err)
	}
	if originURL.Opaque != "" {
		return nil, fmt.Errorf("webauthn: invalid opaque origin %q", origin)
	}

	effectiveDomain := originURL.Hostname() // TODO validate with https://url.spec.whatwg.org/#valid-domain

	// TODO if options.rpId is not a "registrable domain suffix" of and is not equal to effectiveDomain, return error
	rpID := req.RpID

	if rpID == "" {
		rpID = effectiveDomain
	}

	// TODO add support for extensions (bullet point 8 from https://www.w3.org/TR/2020/WD-webauthn-2-20200730/#sctn-discover-from-external-source)
	clientExtensions := make(map[string]interface{})

	clientData := collectedClientData{
		Challenge: base64.RawURLEncoding.EncodeToString(req.Challenge),
		Origin:    fmt.Sprintf("%s://%s", originURL.Scheme, originURL.Host),
		Type:      "webauthn.get",
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

	pinUVAuth, pinProtocol, err := w.userVerification(req.UserVerification, clientDataHash)
	if err != nil {
		return nil, err
	}

	allowList := make([]*ctap2.CredentialDescriptor, 0, len(req.AllowCredentials))
	for _, c := range req.AllowCredentials {
		t, ok := supportedCredentialTypes[c.Type]
		if !ok {
			return nil, fmt.Errorf("webauthn: unsupported excluded credential type %q", c.Type)
		}

		allowList = append(allowList, &ctap2.CredentialDescriptor{
			ID:   c.ID,
			Type: t,
		})
	}

	resp, err := w.t.GetAssertion(&ctap2.GetAssertionRequest{
		RPID:              rpID,
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

func (w *ctap2TWebauthnToken) userVerification(uv string, clientDataHash []byte) ([]byte, ctap2.PinUVAuthProtocolVersion, error) {
	infos, err := w.t.GetInfo()
	if err != nil {
		return nil, 0, err
	}

	var pinUVAuth []byte
	var pinProtocol ctap2.PinUVAuthProtocolVersion

	if uv == "" {
		uv = "preferred"
	}

	switch uv {
	case "discouraged":
		// Do nothing
	case "required":
		if pin, ok := infos.Options["clientPin"]; !ok || !pin {
			return nil, 0, errors.New("webauthn: authenticator does not support user verification")
		}

		pinProtocol = ctap2.PinProtoV1
		pinUVAuth, err = w.pinHandler.Execute(clientDataHash)
		if err != nil {
			return nil, 0, err
		}
	case "preferred":
		// Most authenticators seems to set clientPin option to true when the PIN is set
		// TODO: validate this is a standard way to do that
		if pin, ok := infos.Options["clientPin"]; ok && pin {
			pinProtocol = ctap2.PinProtoV1
			pinUVAuth, err = w.pinHandler.Execute(clientDataHash)
			if err != nil {
				return nil, 0, err
			}
		}
	default:
		return nil, 0, fmt.Errorf("unsupported user verification option %q", uv)
	}

	return pinUVAuth, pinProtocol, nil
}
