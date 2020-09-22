package webauthn

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/flynn/u2f/crypto"
	"github.com/flynn/u2f/u2ftoken"
)

var DefaultCTAP1Timeout = 60

type ctap1WebauthnToken struct {
	t *u2ftoken.Token
}

func (w *ctap1WebauthnToken) Register(origin string, req *RegisterRequest) (*RegisterResponse, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid origin: %w", err)
	}
	if originURL.Opaque != "" {
		return nil, fmt.Errorf("webauthn: invalid opaque origin %q", origin)
	}

	effectiveDomain := originURL.Hostname()
	rpID := req.Rp.ID
	if rpID == "" {
		rpID = effectiveDomain
	}

	useES256 := false
	for _, cp := range req.PubKeyCredParams {
		if crypto.Alg(cp.Alg) == crypto.ES256 {
			useES256 = true
			break
		}
	}
	if !useES256 {
		return nil, errors.New("webauthn: ctap1 protocol require ES256 algorithm")
	}
	if req.AuthenticatorSelection.RequireResidentKey {
		return nil, errors.New("webauth: ctap1 protocol require rk to be false")
	}
	if req.AuthenticatorSelection.UserVerification == "required" {
		return nil, errors.New("webauth: ctap1 protocol does not support required user verification")
	}

	sha := sha256.New()
	if _, err := sha.Write([]byte(rpID)); err != nil {
		return nil, err
	}
	rpIDHash := sha.Sum(nil)

	clientData := collectedClientData{
		Type:      "webauthn.create",
		Challenge: base64.RawURLEncoding.EncodeToString(req.Challenge),
		Origin:    fmt.Sprintf("%s://%s", originURL.Scheme, originURL.Host),
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, err
	}

	sha.Reset()
	if _, err := sha.Write(clientDataJSON); err != nil {
		return nil, err
	}
	clientDataHash := sha.Sum(nil)

	// If the excludeList is not empty, the platform must send signing request with
	// check-only control byte to the CTAP1/U2F authenticator using each of
	// the credential ids (key handles) in the excludeList.
	// If any of them does not result in an error, that means that this is a known device.
	// Afterwards, the platform must still send a dummy registration request (with a dummy appid and invalid challenge)
	// to CTAP1/U2F authenticators that it believes are excluded. This makes it so the user still needs to touch
	// the CTAP1/U2F authenticator before the RP gets told that the token is already registered.
	var errCredentialExcluded error
	for _, excludedCred := range req.ExcludeCredentials {
		if err := w.t.CheckAuthenticate(u2ftoken.AuthenticateRequest{
			Application: rpIDHash,
			Challenge:   clientDataHash,
			KeyHandle:   excludedCred.ID,
		}); err != u2ftoken.ErrUnknownKeyHandle {
			rpIDHash = make([]byte, 32)
			clientDataHash = make([]byte, 32)
			errCredentialExcluded = errors.New("webauthn: excluded credential")
			break
		}
	}

	if req.Timeout == 0 {
		req.Timeout = DefaultCTAP1Timeout
	}

	resp, err := w.registerWithTimeout(&u2ftoken.RegisterRequest{
		Application: rpIDHash,
		Challenge:   clientDataHash,
	}, time.Duration(req.Timeout))
	if err != nil {
		return nil, err
	}

	if errCredentialExcluded != nil {
		return nil, errCredentialExcluded
	}

	authData := make([]byte, 37)
	copy(authData, rpIDHash)
	// Let flags be a byte whose zeroth bit (bit 0, UP) is set,
	// and whose sixth bit (bit 6, AT) is set, and all other bits
	// are zero (bit zero is the least significant bit)
	authData[32] = 0x41
	// 4 next bytes are left to 0
	// 16 bytes for AAGUID (all zeros) + 2 bytes for credID len + credID (keyHandle) + 77 bytes COSEKey
	attestedCredData := make([]byte, 16, 143+len(resp.KeyHandle))

	x, y := elliptic.Unmarshal(elliptic.P256(), resp.UserPublicKey)
	coseKey := crypto.COSEKey{
		KeyType: crypto.EC2,
		Alg:     crypto.ES256,
		Curve:   crypto.P256,
		X:       x.Bytes(),
		Y:       y.Bytes(),
	}

	coseKeyBytes, err := coseKey.CBOREncode()
	if err != nil {
		return nil, err
	}

	khLen := make([]byte, 2)
	binary.BigEndian.PutUint16(khLen, uint16(len(resp.KeyHandle)))
	attestedCredData = append(attestedCredData, khLen...)
	attestedCredData = append(attestedCredData, resp.KeyHandle...)
	attestedCredData = append(attestedCredData, coseKeyBytes...)

	authData = append(authData, attestedCredData...)

	return &RegisterResponse{
		ID: resp.KeyHandle,
		Response: AttestationResponse{
			AttestationObject: AttestationObject{
				Fmt: "fido-u2f",
				AttSmt: map[string]interface{}{
					"sig": resp.Signature,
					"x5c": []interface{}{resp.AttestationCertificate},
				},
				AuthData: authData,
			},
			ClientDataJSON: clientDataJSON,
		},
	}, nil
}

func (w *ctap1WebauthnToken) Authenticate(origin string, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid origin: %w", err)
	}
	if originURL.Opaque != "" {
		return nil, fmt.Errorf("webauthn: invalid opaque origin %q", origin)
	}

	effectiveDomain := originURL.Hostname()
	rpID := req.RpID
	if rpID == "" {
		rpID = effectiveDomain
	}

	if len(req.AllowCredentials) == 0 {
		return nil, errors.New("webauthn: ctap1 require at least one credential")
	}
	if req.UserVerification == "required" {
		return nil, errors.New("webauthn: ctap1 does not support user verification")
	}

	if req.Timeout == 0 {
		req.Timeout = DefaultCTAP1Timeout
	}

	sha := sha256.New()
	if _, err := sha.Write([]byte(rpID)); err != nil {
		return nil, err
	}
	rpIDHash := sha.Sum(nil)

	clientData := collectedClientData{
		Challenge: base64.RawURLEncoding.EncodeToString(req.Challenge),
		Origin:    fmt.Sprintf("%s://%s", originURL.Scheme, originURL.Host),
		Type:      "webauthn.get",
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return nil, err
	}

	sha.Reset()
	if _, err := sha.Write(clientDataJSON); err != nil {
		return nil, err
	}
	clientDataHash := sha.Sum(nil)

	authReq := &u2ftoken.AuthenticateRequest{
		Challenge:   clientDataHash,
		Application: rpIDHash,
		KeyHandle:   req.AllowCredentials[0].ID,
	}

	if len(req.AllowCredentials) > 1 {
		for _, cred := range req.AllowCredentials {
			authReq.KeyHandle = cred.ID
			if err := w.t.CheckAuthenticate(*authReq); err == nil {
				break
			}
		}
	}

	authResp, err := w.authenticateWithTimeout(authReq, time.Duration(req.Timeout))
	if err != nil {
		return nil, err
	}

	authData := make([]byte, 37)
	copy(authData, rpIDHash)
	authData[32] = authResp.RawResponse[0]
	binary.BigEndian.PutUint32(authData[33:], authResp.Counter)

	return &AuthenticateResponse{
		ID: authReq.KeyHandle,
		Response: AssertionResponse{
			AuthenticatorData: authData,
			Signature:         authResp.Signature,
			ClientDataJSON:    clientDataJSON,
		},
	}, nil
}

func (w *ctap1WebauthnToken) registerWithTimeout(req *u2ftoken.RegisterRequest, timeout time.Duration) (*u2ftoken.RegisterResponse, error) {
	for {
		select {
		case <-time.After(timeout * time.Second):
			return nil, u2ftoken.ErrPresenceRequired
		default:
			resp, err := w.t.Register(*req)
			if err != nil {
				if err != u2ftoken.ErrPresenceRequired {
					return nil, err
				}
				time.Sleep(200 * time.Millisecond)
			} else {
				return resp, nil
			}
		}
	}
}

func (w *ctap1WebauthnToken) authenticateWithTimeout(req *u2ftoken.AuthenticateRequest, timeout time.Duration) (*u2ftoken.AuthenticateResponse, error) {
	for {
		select {
		case <-time.After(timeout * time.Second):
			return nil, u2ftoken.ErrPresenceRequired
		default:
			resp, err := w.t.Authenticate(*req)
			if err != nil {
				if err != u2ftoken.ErrPresenceRequired {
					return nil, err
				}
				time.Sleep(200 * time.Millisecond)
			} else {
				return resp, nil
			}
		}
	}
}
