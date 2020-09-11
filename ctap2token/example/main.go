package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/u2fhid"
	"github.com/grantae/certinfo"
)

func main() {
	devices, err := u2fhid.Devices()
	if err != nil {
		panic(err)
	}

	for _, d := range devices {
		dev, err := u2fhid.Open(d)
		if err != nil {
			panic(err)
		}

		token := ctap2token.NewToken(dev)

		infos, err := token.GetInfo()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Token infos:\n%#v\n", infos)

		// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret
		fmt.Println("Retrieving key agreement from authenticator")
		cp1, err := token.ClientPIN(&ctap2token.ClientPINRequest{
			PinProtocol: ctap2token.PinProtoV1,
			SubCommand:  ctap2token.GetKeyAgreement,
		})
		if err != nil {
			panic(err)
		}

		fmt.Println("Generating platform key pair")
		b, bGX, bGY, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		aG := cp1.KeyAgreement
		aGX := new(big.Int)
		aGX.SetBytes(aG.X)

		aGY := new(big.Int)
		aGY.SetBytes(aG.Y)

		rX, _ := elliptic.P256().ScalarMult(aGX, aGY, b)

		h := sha256.New()
		_, err = h.Write(rX.Bytes())
		if err != nil {
			panic(err)
		}

		sharedSecret := h.Sum(nil)
		fmt.Println("Generated shared secret")

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter PIN: ")
		userPIN, _ := reader.ReadString('\n')

		h.Reset()
		_, err = h.Write([]byte(strings.TrimSpace(userPIN)))
		if err != nil {
			panic(err)
		}

		pinHash := h.Sum(nil)
		pinHash = pinHash[:aes.BlockSize]

		pinHashEnc := make([]byte, aes.BlockSize)
		c, err := aes.NewCipher(sharedSecret)
		if err != nil {
			panic(err)
		}
		iv := make([]byte, aes.BlockSize)
		cbcEnc := cipher.NewCBCEncrypter(c, iv)
		cbcEnc.CryptBlocks(pinHashEnc, pinHash)
		fmt.Println("Encrypted user PIN using shared secret")

		pinResp, err := token.ClientPIN(&ctap2token.ClientPINRequest{
			SubCommand: ctap2token.GetPinToken,
			KeyAgreement: &ctap2token.COSEKey{
				X:       bGX.Bytes(),
				Y:       bGY.Bytes(),
				KeyType: ctap2token.EC2,            // not required ?
				Curve:   ctap2token.P256,           // not required ?
				Alg:     ctap2token.ECDHES_HKDF256, // not required ?
			},
			PinHashEnc:  pinHashEnc,
			PinProtocol: ctap2token.PinProtoV1,
		})
		if err != nil {
			panic(err)
		}

		// Decrypt pinToken using shared secret
		pinHashDec := make([]byte, aes.BlockSize)
		cbcDec := cipher.NewCBCDecrypter(c, iv)
		cbcDec.CryptBlocks(pinHashDec, pinResp.PinToken)
		fmt.Println("Decrypted authenticator pinToken")

		clientDataHash := make([]byte, 32)
		if _, err := rand.Read(clientDataHash); err != nil {
			panic(err)
		}

		userID := make([]byte, 32)
		if _, err := rand.Read(userID); err != nil {
			panic(err)
		}

		mac := hmac.New(sha256.New, pinHashDec)
		_, err = mac.Write(clientDataHash)
		if err != nil {
			panic(err)
		}

		pinAuth := mac.Sum(nil)
		pinAuth = pinAuth[:16]
		fmt.Println("Signed clientData with pinToken")

		fmt.Println("Sending makeCredential request, please press authenticator button...")
		req := &ctap2token.MakeCredentialRequest{
			ClientDataHash: clientDataHash,
			RP: ctap2token.CredentialRpEntity{
				ID:   "example.com",
				Name: "Acme",
			},
			User: ctap2token.CredentialUserEntity{
				ID:          userID,
				Icon:        "https://pics.example.com/00/p/aBjjjpqPb.png",
				Name:        "johnpsmith@example.com",
				DisplayName: "John P. Smith",
			},
			PubKeyCredParams: []ctap2token.CredentialParam{
				ctap2token.PublicKeyES256,
				ctap2token.PublicKeyRS256,
			},
			PinAuth:     pinAuth,
			PinProtocol: ctap2token.PinProtoV1,
		}

		resp, err := token.MakeCredential(req)
		if err != nil {
			panic(err)
		}
		fmt.Println("Success creating credential!")

		x509certs, ok := resp.AttSmt["x5c"]
		if !ok {
			panic("no x5c field")
		}

		fmt.Println(len(x509certs.([]interface{})))

		x509cert := x509certs.([]interface{})[0].([]byte)
		cert, err := x509.ParseCertificate(x509cert)
		if err != nil {
			panic(err)
		}
		certStr, err := certinfo.CertificateText(cert)
		if err != nil {
			panic(err)
		}

		fmt.Println(certStr)
		fmt.Println("Signature:")
		fmt.Printf("%x\n", resp.AttSmt["sig"])
		fmt.Println("AuthData:")
		fmt.Printf("%x\n", resp.AuthData)
	}
}
