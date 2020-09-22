package webauthn

import (
	"github.com/flynn/u2f/u2ftoken"
)

type ctap1WebauthnToken struct {
	t *u2ftoken.Token
}

func (w *ctap1WebauthnToken) Register(origin string, req *RegisterRequest) (*RegisterResponse, error) {
	panic("not implemented yet")
}
func (w *ctap1WebauthnToken) Authenticate(origin string, req *AuthenticateRequest) (*AuthenticateResponse, error) {
	panic("not implemented yet")
}
