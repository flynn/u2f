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

func (a *Webauthn) Register(ctx context.Context, origin string, req *RegisterRequest) (*RegisterResponse, error) {
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

	authenticators, userPIN, err := a.selectAuthenticators(ctx, req.AuthenticatorSelection)
	if err != nil {
		return nil, err
	}

	type authenticatorResponse struct {
		authenticator Authenticator
		resp          *RegisterResponse
		err           error
	}

	respChan := make(chan *authenticatorResponse)

	timeout := time.Duration(req.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// Send the request to all selected authenticators
	for _, authenticator := range authenticators {
		go func(a Authenticator) {
			// make sure the HID connection stays open at least as long as the request needs it.
			a.SetResponseTimeout(timeout)
			resp, err := a.Register(ctx, req, &RequestParams{
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
		// cancel any other pending CTAP1 authenticators
		cancel()
		closeAll(authenticators)
		return authResp.resp, authResp.err
	case <-time.After(time.Duration(req.Timeout) * time.Second):
		cancel()
		closeAll(authenticators)
		return nil, errors.New("webauthn: timeout waiting for authenticator response")
	}
}

func (a *Webauthn) Authenticate(ctx context.Context, origin string, req *AuthenticateRequest) (*AuthenticateResponse, error) {
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

	authenticators, userPIN, err := a.selectAuthenticators(ctx, AuthenticatorSelection{
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

	timeout := time.Duration(req.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)

	// Send the request to all selected authenticators
	for _, authenticator := range authenticators {
		go func(a Authenticator) {
			// make sure the HID connection stays open at least as long as the request needs it.
			a.SetResponseTimeout(timeout)
			resp, err := a.Authenticate(ctx, req, &RequestParams{
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
		// cancel any other pending CTAP1 authenticators
		cancel()
		closeAll(authenticators)
		return authResp.resp, authResp.err
	case <-time.After(time.Duration(req.Timeout) * time.Second):
		closeAll(authenticators)
		cancel()
		return nil, errors.New("webauthn: timeout waiting for authenticator response")
	}
}

func closeAll(auths []Authenticator) {
	for _, a := range auths {
		a.Close()
	}
}

// selectAuthenticators guides the user into selecting the authenticator to communicate with.
// One or multiple devices can be returned depending on their supported protocols and the AuthenticatorSelection
// requirements.
// If user verification is required, the user will be prompted to enter the device PIN, or to set it. The PIN will
// be returned in order to be exchanged later for a pinAuth code (see pin.ExchangeUserPinToPinAuth).
func (a *Webauthn) selectAuthenticators(ctx context.Context, opts AuthenticatorSelection) ([]Authenticator, []byte, error) {
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
				if dev.CapabilityCBOR {
					t := ctap2.NewToken(dev)
					info, err := t.GetInfo()
					if err != nil {
						return nil, nil, err
					}

					current = &ctap2WebauthnToken{
						t:       t,
						options: info.Options,
					}
				} else {
					current = &ctap1WebauthnToken{
						t: u2ftoken.NewToken(dev),
					}
				}

				// Skip devices not fullfilling request requirements
				if opts.RequireResidentKey && !current.SupportRK() {
					dev.Close()
					continue
				}
				if opts.UserVerification == UVDiscouraged && current.RequireUV() {
					dev.Close()
					continue
				}
				if opts.UserVerification == UVRequired && !dev.CapabilityCBOR {
					dev.Close()
					continue
				}

				selected = append(selected, current)
			}
		}
	}

	// When multiple devices are present and UV is needed, we must guide the user to select a single device.
	// This is done by sending fake CTAP1 register requests to all devices, with a test-user-presence flag.
	// The first device to reply with a non-error is assumed selected by the user.
	if opts.UserVerification != UVDiscouraged {
		// if we require UV, have multiple devies, and at least one
		// support CTAP2, we must request the user to select the device first.
		// when having multiple CTAP1 devices only, we just skip selection, the user presence test will
		// select the device.
		ctap2DevicePresent := false
		for _, s := range selected {
			if _, isCTAP2 := s.(*ctap2WebauthnToken); isCTAP2 {
				ctap2DevicePresent = true
				break
			}
		}

		selectedAuth := selected[0]
		if len(selected) > 1 && ctap2DevicePresent {
			a.pinHandler.Println("Multiple security keys found. Please select one by touching it...")
			respChan := make(chan Authenticator)
			ctx, cancel := context.WithTimeout(ctx, a.deviceSelectionTimeout)
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
				// cancel CTAP1 selection routines
				cancel()
				for _, s := range selected {
					if s == selectedAuth {
						continue
					}
					// send a cancel command to CTAP2 devices (they cannot be canceled via go context)
					if a, ok := s.(*ctap2WebauthnToken); ok {
						a.t.Cancel()
					}
					// close all devices not selected
					s.Close()
				}
				selected = []Authenticator{selectedAuth}
				a.pinHandler.Println("device selected!")
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}

		// Collect PIN or guide user to set a PIN on CTAP2 authenticators
		if ctap2Auth, isCTAP2 := selectedAuth.(*ctap2WebauthnToken); isCTAP2 {
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
		a.pinHandler.Println("Confirm presence by touching the authenticator when it blinks...")

	}

	return selected, userPIN, nil
}
