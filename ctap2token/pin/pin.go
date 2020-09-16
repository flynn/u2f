package pin

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math/big"
	"strings"

	"github.com/flynn/u2f/ctap2token"
)

type PINHandler interface {
	Execute(clientDataHash []byte) (ctap2token.PinUVAuth, error)
}

type InteractiveHandler struct {
	Stdin  io.Reader
	Stdout io.Writer

	token *ctap2token.Token
}

var _ PINHandler = (*InteractiveHandler)(nil)

// NewInteractiveHandler returns an interactive PINHandler, which will read
// the user PIN  from the provided reader
func NewInteractiveHandler(t *ctap2token.Token, stdin io.Reader) *InteractiveHandler {
	return &InteractiveHandler{
		token: t,
		Stdin: stdin,
	}
}

// Execute performs the operations described by the FIDO specification in order to securely
// obtain a token from the authenticator which can be used to verify the user.
// see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret
func (h *InteractiveHandler) Execute(clientDataHash []byte) (ctap2token.PinUVAuth, error) {
	reader := bufio.NewReader(h.Stdin)
	userPIN, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	userPIN = strings.TrimSpace(userPIN)

	return exchangeUserPinToPinAuth(h.token, []byte(userPIN), clientDataHash)
}

func exchangeUserPinToPinAuth(token *ctap2token.Token, userPIN, clientDataHash []byte) ([]byte, error) {
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
	pinHashEnc := make([]byte, aes.BlockSize)
	c, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	cbcEnc := cipher.NewCBCEncrypter(c, iv)
	cbcEnc.CryptBlocks(pinHashEnc, pinHash)

	return pinHashEnc, nil
}

func getPINToken(token *ctap2token.Token, encPinHash []byte, bGX, bGY *big.Int) ([]byte, error) {
	pinResp, err := token.ClientPIN(&ctap2token.ClientPINRequest{
		SubCommand: ctap2token.GetPINUvAuthTokenUsingPIN,
		KeyAgreement: &ctap2token.COSEKey{
			X:       bGX.Bytes(),
			Y:       bGY.Bytes(),
			KeyType: ctap2token.EC2,
			Curve:   ctap2token.P256,
			Alg:     ctap2token.ECDHES_HKDF256,
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
	clearPinToken := make([]byte, aes.BlockSize)
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
