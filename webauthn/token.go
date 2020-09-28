package webauthn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

// DefaultResponseTimeout is the default timeout, in seconds, waiting for a response from a device
var DefaultResponseTimeout = 60

var (
	// DefaultDeviceSelectionTimeout is the default timeout, in seconds, waiting for the user to select a device
	DefaultDeviceSelectionTimeout = 30
	// MaxAllowedResponseTimeout defines the maximum response timeout, in seconds.
	// When exceeding, the timeout will be forced to this value.
	MaxAllowedResponseTimeout = 120
)

var emptyAAGUID = make([]byte, 16)

type Webauthn struct {
	debug                  bool
	pinHandler             pin.PINHandler
	deviceSelectionTimeout time.Duration
}

type WebauthnOption func(*Webauthn)

func WithDebug(enabled bool) WebauthnOption {
	return func(a *Webauthn) {
		a.debug = enabled
	}
}

func WithCTAP2PinHandler(pinHandler pin.PINHandler) WebauthnOption {
	return func(a *Webauthn) {
		a.pinHandler = pinHandler
	}
}

func WithDeviceSelectionTimeout(d time.Duration) WebauthnOption {
	return func(a *Webauthn) {
		a.deviceSelectionTimeout = d
	}
}

func New(opts ...WebauthnOption) *Webauthn {
	a := &Webauthn{
		pinHandler:             pin.NewInteractiveHandler(),
		debug:                  false,
		deviceSelectionTimeout: time.Duration(DefaultDeviceSelectionTimeout) * time.Second,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Webauthn) Register(origin string, req *RegisterRequest) (*RegisterResponse, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid origin: %w", err)
	}
	if originURL.Opaque != "" {
		return nil, fmt.Errorf("webauthn: invalid opaque origin %q", origin)
	}

	if req.Timeout <= 0 {
		req.Timeout = DefaultResponseTimeout
	}
	if req.Timeout > MaxAllowedResponseTimeout {
		req.Timeout = MaxAllowedResponseTimeout
	}

	if req.Rp.ID == "" {
		req.Rp.ID = originURL.Hostname()
	}
	// TODO check RP ID is a valid domain (https://www.w3.org/TR/webauthn/#CreateCred-DetermineRpId)

	authenticators, userPIN, err := a.selectAuthenticators(req.AuthenticatorSelection)
	if err != nil {
		return nil, err
	}

	type authenticatorResponse struct {
		authenticator Authenticator
		resp          *RegisterResponse
		err           error
	}

	respChan := make(chan *authenticatorResponse)

	// Send the request to all selected authenticators
	for _, authenticator := range authenticators {
		go func(a Authenticator) {
			a.SetResponseTimeout(time.Duration(req.Timeout) * time.Second)
			resp, err := a.Register(req, &RequestParams{
				ClientData: CollectedClientData{
					Type:      "webauthn.create",
					Challenge: base64.RawURLEncoding.EncodeToString(req.Challenge),
					Origin:    fmt.Sprintf("%s://%s", originURL.Scheme, originURL.Host),
				},
				UserPIN: userPIN,
			})
			respChan <- &authenticatorResponse{
				authenticator: a,
				resp:          resp,
				err:           err,
			}
		}(authenticator)
	}

	select {
	case authResp := <-respChan:
		// cancel any other pending authenticators
		for _, a := range authenticators {
			if a == authResp.authenticator {
				continue
			}
			a.Cancel()
		}

		if authResp.err != nil {
			return nil, authResp.err
		}
		return authResp.resp, nil
	case <-time.After(time.Duration(req.Timeout) * time.Second):
		for _, a := range authenticators {
			a.Cancel()
		}
		return nil, errors.New("webauthn: timeout waiting for authenticator response")
	}
}

func (a *Webauthn) Authenticate(origin string, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	originURL, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid origin: %w", err)
	}
	if originURL.Opaque != "" {
		return nil, fmt.Errorf("webauthn: invalid opaque origin %q", origin)
	}

	if req.Timeout <= 0 {
		req.Timeout = DefaultResponseTimeout
	}
	if req.Timeout > MaxAllowedResponseTimeout {
		req.Timeout = MaxAllowedResponseTimeout
	}

	if req.RpID == "" {
		req.RpID = originURL.Hostname()
	}
	// TODO check RP ID is a valid domain (https://www.w3.org/TR/webauthn/#CreateCred-DetermineRpId)

	authenticators, userPIN, err := a.selectAuthenticators(AuthenticatorSelection{
		UserVerification: req.UserVerification,
	})
	if err != nil {
		return nil, err
	}

	type authenticatorResponse struct {
		authenticator Authenticator
		resp          *AuthenticateResponse
		err           error
	}

	respChan := make(chan *authenticatorResponse)

	// Send the request to all selected authenticators
	for _, authenticator := range authenticators {
		go func(a Authenticator) {
			a.SetResponseTimeout(time.Duration(req.Timeout) * time.Second)
			resp, err := a.Authenticate(req, &RequestParams{
				ClientData: CollectedClientData{
					Type:      "webauthn.get",
					Challenge: base64.RawURLEncoding.EncodeToString(req.Challenge),
					Origin:    fmt.Sprintf("%s://%s", originURL.Scheme, originURL.Host),
				},
				UserPIN: userPIN,
			})
			respChan <- &authenticatorResponse{
				authenticator: a,
				resp:          resp,
				err:           err,
			}
		}(authenticator)
	}

	select {
	case authResp := <-respChan:
		// cancel any other pending authenticators
		for _, a := range authenticators {
			if a == authResp.authenticator {
				continue
			}
			a.Cancel()
		}

		if authResp.err != nil {
			return nil, authResp.err
		}
		return authResp.resp, nil
	case <-time.After(time.Duration(req.Timeout) * time.Second):
		for _, a := range authenticators {
			a.Cancel()
		}
		return nil, errors.New("webauthn: timeout waiting for authenticator response")
	}
}

// selectAuthenticators guide the user into selecting the authenticator to communicate with.
// One or multiple devices can be returned depending on their supported protocols and the AuthenticatorSelection
// requirements.
// If user verification is required, the user will be prompted to enter the device PIN, or to set it. The PIN will
// be returned in order to be exchanged later for a pinAuth code (see pin.ExchangeUserPinToPinAuth).
func (a *Webauthn) selectAuthenticators(opts AuthenticatorSelection) ([]Authenticator, []byte, error) {
	var selected []Authenticator
	var userPIN []byte

	for len(selected) == 0 {
		select {
		case <-time.After(a.deviceSelectionTimeout):
			return nil, nil, errors.New("webauthn: timeout while waiting for authenticator")
		default:
			u2fDevInfos, err := u2fhid.Devices()
			if err != nil {
				return nil, nil, err
			}
			if len(u2fDevInfos) == 0 {
				time.Sleep(200 * time.Millisecond)
				continue
			}

			for _, devInfo := range u2fDevInfos {
				dev, err := u2fhid.Open(devInfo)
				if err != nil {
					return nil, nil, err
				}

				var current Authenticator
				var isCTAP2 bool
				t := ctap2.NewToken(dev)
				if info, err := t.GetInfo(); err == nil {
					current = &ctap2WebauthnToken{
						t:       t,
						options: info.Options,
					}
					isCTAP2 = true
				} else {
					current = &ctap1WebauthnToken{
						t: u2ftoken.NewToken(dev),
					}
				}

				// Skip devices not fullfilling request requirements
				if opts.RequireResidentKey && !current.SupportRK() {
					continue
				}
				if opts.UserVerification == UVDiscouraged && current.RequireUV() {
					continue
				}
				if opts.UserVerification == UVRequired && !isCTAP2 {
					continue
				}

				selected = append(selected, current)
			}
		}
	}

	// When multiple devices are present and UV is needed, we must guide the user to select a single device.
	// This is done by sending fake ctap1 register requests to all devices, with a test-user-presence flag.
	// The first device to reply a non error is assumed selected by the user.
	if opts.UserVerification != UVDiscouraged {
		selectedAuth := selected[0]

		if len(selected) > 1 {
			a.pinHandler.Println("multiple security keys found. Please select one by touching it...")
			respChan := make(chan Authenticator)
			ctx, cancel := context.WithTimeout(context.Background(), a.deviceSelectionTimeout)
			defer cancel()
			for _, s := range selected {
				go func(auth Authenticator) {
					err := auth.AuthenticatorSelection(ctx)
					if err == nil {
						respChan <- auth
					}
				}(s)
			}

			select {
			case selectedAuth = <-respChan:
				selected = []Authenticator{selectedAuth}
				a.pinHandler.Println("device selected!")
				cancel() // cancel other selection routines
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}

		// Collect PIN or guide user to set a PIN on CTAP2 authenticators
		ctap2Auth, isCTAP2 := selectedAuth.(*ctap2WebauthnToken)
		if isCTAP2 {
			var err error
			if !selectedAuth.RequireUV() {
				userPIN, err = a.pinHandler.SetPIN(ctap2Auth.t)
				if err != nil {
					return nil, nil, err
				}
			} else {
				userPIN, err = a.pinHandler.ReadPIN()
				if err != nil {
					return nil, nil, err
				}
			}
		}
		a.pinHandler.Println("confirm presence on authenticator when it will blink...")

	}

	return selected, userPIN, nil
}
