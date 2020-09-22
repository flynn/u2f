package webauthn

import (
	ctap2 "github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/u2ftoken"
)

var supportedCredentialTypes = map[string]ctap2.CredentialType{
	string(ctap2.PublicKey): ctap2.PublicKey,
}
var supportedTransports = map[string]ctap2.AuthenticatorTransport{
	string(ctap2.USB): ctap2.USB,
}

var emptyAAGUID = make([]byte, 16)

// NewToken returns a new WebAuthn capable token.
// It will first try to communicate with the device using FIDO2 / CTAP2 protocol,
// and fallback using U2F / CTAP1 on failure.
// A pinHandler is required when using a CTAP2 compatible authenticator with a configured PIN, when requests
// require user verification.
func NewToken(d Device, pinHandler pin.PINHandler) (Token, error) {
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
