package pin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/flynn/u2f/crypto"
	"github.com/flynn/u2f/ctap2token"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	PinLengthMin = 4
	PinLengthMax = 63
)

type PINHandler interface {
	ReadPIN() ([]byte, error)
	SetPIN(token *ctap2token.Token) ([]byte, error)
	Println(msg ...interface{})
}

type InteractiveHandler struct {
	Stdin  *os.File
	Stdout *os.File
}

var _ PINHandler = (*InteractiveHandler)(nil)

// NewInteractiveHandler returns an interactive PINHandler, which will read
// the user PIN  from the provided reader
func NewInteractiveHandler() *InteractiveHandler {
	return &InteractiveHandler{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
	}
}

func (h *InteractiveHandler) ReadPIN() ([]byte, error) {
	_, err := fmt.Fprint(h.Stdout, "enter current device PIN: ")
	if err != nil {
		return nil, err
	}

	return getpasswd(h.Stdin)
}

func (h *InteractiveHandler) SetPIN(token *ctap2token.Token) ([]byte, error) {
	_, err := fmt.Fprint(h.Stdout, "enter new device PIN: ")
	if err != nil {
		return nil, err
	}
	userPIN, err := getpasswd(h.Stdin)
	if err != nil {
		return nil, err
	}

	// checks from https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#client-pin-uv-support
	if l := len(userPIN); l < PinLengthMin || l > PinLengthMax {
		return nil, errors.New("invalid pin, must be between 4 to 63 bytes")
	}
	if userPIN[len(userPIN)-1] == 0 {
		return nil, errors.New("invalid pin, must not end with a NUL byte")
	}
	_, err = fmt.Fprint(h.Stdout, "confirm new device PIN: ")
	if err != nil {
		return nil, err
	}
	confirmPIN, err := getpasswd(h.Stdin)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(userPIN, confirmPIN) {
		return nil, errors.New("pin confirmation mismatch")
	}

	aGX, aGY, err := getTokenKeyAgreement(token)
	if err != nil {
		return nil, err
	}
	b, bGX, bGY, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := computeSharedSecret(b, aGX, aGY)
	if err != nil {
		return nil, err
	}

	// Normalize pin size to 64 bytes, padding with zeroes
	newPIN := make([]byte, 64)
	copy(newPIN, userPIN)
	newPinEnc, err := aesCBCEncrypt(sharedSecret, newPIN)
	if err != nil {
		return nil, err
	}

	keyAgreement := &crypto.COSEKey{
		X:       bGX.Bytes(),
		Y:       bGY.Bytes(),
		KeyType: crypto.EC2,
		Curve:   crypto.P256,
		Alg:     crypto.ECDHES_HKDF256,
	}

	mac := hmac.New(sha256.New, sharedSecret)
	_, err = mac.Write(newPinEnc)
	if err != nil {
		return nil, err
	}
	pinAuth := mac.Sum(nil)[:16]

	_, err = token.ClientPIN(&ctap2token.ClientPINRequest{
		SubCommand:   ctap2token.SetPIN,
		NewPinEnc:    newPinEnc,
		KeyAgreement: keyAgreement,
		PinProtocol:  ctap2token.PinProtoV1,
		PinAuth:      pinAuth,
	})
	if err != nil {
		return nil, err
	}
	return userPIN, nil
}

func (h *InteractiveHandler) Println(msg ...interface{}) {
	fmt.Fprintln(h.Stdout, msg...)
}

// ExchangeUserPinToPinAuth performs the operations described by the FIDO specification in order to securely
// obtain a token from the authenticator which can be used to verify the user.
// see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret
func ExchangeUserPinToPinAuth(token *ctap2token.Token, userPIN, clientDataHash []byte) ([]byte, error) {
	b, bGX, bGY, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	aGX, aGY, err := getTokenKeyAgreement(token)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := computeSharedSecret(b, aGX, aGY)
	if err != nil {
		return nil, err
	}

	encPinHash, err := hashEncryptPIN(userPIN, sharedSecret)
	if err != nil {
		return nil, err
	}

	pinToken, err := getPINToken(token, encPinHash, bGX, bGY)
	if err != nil {
		return nil, err
	}

	return computePINAuth(pinToken, sharedSecret, clientDataHash)
}

func getTokenKeyAgreement(token *ctap2token.Token) (aGX, aGY *big.Int, err error) {
	pinResp, err := token.ClientPIN(&ctap2token.ClientPINRequest{
		PinProtocol: ctap2token.PinProtoV1,
		SubCommand:  ctap2token.GetKeyAgreement,
	})
	if err != nil {
		return nil, nil, err
	}

	aGX = new(big.Int)
	aGX.SetBytes(pinResp.KeyAgreement.X)

	aGY = new(big.Int)
	aGY.SetBytes(pinResp.KeyAgreement.Y)

	return aGX, aGY, nil
}

func computeSharedSecret(b []byte, aGX, aGY *big.Int) ([]byte, error) {
	rX, _ := elliptic.P256().ScalarMult(aGX, aGY, b)
	sha := sha256.New()
	_, err := sha.Write(rX.Bytes())
	if err != nil {
		return nil, err
	}

	return sha.Sum(nil), nil
}

func hashEncryptPIN(userPIN []byte, sharedSecret []byte) ([]byte, error) {
	sha := sha256.New()
	_, err := sha.Write(userPIN)
	if err != nil {
		return nil, err
	}

	pinHash := sha.Sum(nil)
	pinHash = pinHash[:aes.BlockSize]

	// encrypt pinHash with AES-CBC using shared secret
	return aesCBCEncrypt(sharedSecret, pinHash)
}

func aesCBCEncrypt(sharedSecret, data []byte) ([]byte, error) {
	dataEnc := make([]byte, len(data))
	c, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	cbcEnc := cipher.NewCBCEncrypter(c, iv)
	cbcEnc.CryptBlocks(dataEnc, data)

	return dataEnc, nil
}

func getPINToken(token *ctap2token.Token, encPinHash []byte, bGX, bGY *big.Int) ([]byte, error) {
	pinResp, err := token.ClientPIN(&ctap2token.ClientPINRequest{
		SubCommand: ctap2token.GetPINUvAuthTokenUsingPIN,
		KeyAgreement: &crypto.COSEKey{
			X:       bGX.Bytes(),
			Y:       bGY.Bytes(),
			KeyType: crypto.EC2,
			Curve:   crypto.P256,
			Alg:     crypto.ECDHES_HKDF256,
		},
		PinHashEnc:  encPinHash,
		PinProtocol: ctap2token.PinProtoV1,
	})
	if err != nil {
		return nil, err
	}

	return pinResp.PinToken, nil
}

func computePINAuth(pinToken, sharedSecret, data []byte) ([]byte, error) {
	// decrypt pinToken using AES-CBC with shared secret
	clearPinToken := make([]byte, len(data))
	c, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	cbcDec := cipher.NewCBCDecrypter(c, iv)
	cbcDec.CryptBlocks(clearPinToken, pinToken)

	// compute and return pinAuth
	mac := hmac.New(sha256.New, clearPinToken)
	_, err = mac.Write(data)
	if err != nil {
		return nil, err
	}
	pinAuth := mac.Sum(nil)
	return pinAuth[:16], nil
}

func getpasswd(r *os.File) ([]byte, error) {
	pin, err := terminal.ReadPassword(int(r.Fd()))
	// since terminal disable tty echo, we need a newline to keep the display organized
	fmt.Println()
	return pin, err
}
