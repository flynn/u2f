package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/u2fhid"
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
			fmt.Printf("failed to retrieve token info (%v), is the token supporting CTAP2 ?\n", err)
			continue
		}
		fmt.Printf("Token infos:\n%#v\n", infos)

		clientDataHash := make([]byte, 32)
		if _, err := rand.Read(clientDataHash); err != nil {
			panic(err)
		}

		userID := make([]byte, 32)
		if _, err := rand.Read(userID); err != nil {
			panic(err)
		}

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
		}

		// first try without user verification
		fmt.Println("Sending makeCredential request, please press authenticator button...")
		resp, err := token.MakeCredential(req)
		if err != nil {
			// retry but with user verification
			if errors.Unwrap(err) != ctap2token.ErrPinRequired {
				panic(err)
			}

			pinHandler := pin.NewInteractiveHandler()
			userPIN, err := pinHandler.ReadPIN()
			if err != nil {
				panic(err)
			}

			pinAuth, err := pin.ExchangeUserPinToPinAuth(token, userPIN, clientDataHash)
			if err != nil {
				panic(err)
			}
			req.PinUVAuth = &pinAuth
			req.PinUVAuthProtocol = ctap2token.PinProtoV1

			resp, err = token.MakeCredential(req)
			if err != nil {
				panic(err)
			}
		}
		fmt.Println("Success creating credential")

		// Verify signature with the X509 certificate from the attestation statement
		x509certs, ok := resp.AttSmt["x5c"]
		if !ok {
			panic("no x5c field")
		}

		x509cert := x509certs.([]interface{})[0].([]byte)
		cert, err := x509.ParseCertificate(x509cert)
		if err != nil {
			panic(err)
		}

		signed := append(resp.AuthData, clientDataHash...)
		if err := cert.CheckSignature(x509.ECDSAWithSHA256, signed, resp.AttSmt["sig"].([]byte)); err != nil {
			panic(err)
		}
		fmt.Println("MakeCredentials signature is valid!")

		mcpAuthData, err := resp.AuthData.Parse()
		if err != nil {
			panic(err)
		}
		fmt.Printf("credentialID: %x\n", mcpAuthData.AttestedCredentialData.CredentialID)

		fmt.Println("Sending GetAssertion request, please press authenticator button...")
		getAssertionResp, err := token.GetAssertion(&ctap2token.GetAssertionRequest{
			RPID: "example.com",
			AllowList: []*ctap2token.CredentialDescriptor{
				{
					ID:         mcpAuthData.AttestedCredentialData.CredentialID,
					Transports: []ctap2token.AuthenticatorTransport{ctap2token.USB},
					Type:       ctap2token.PublicKey,
				},
			},
			ClientDataHash: clientDataHash,
			// enable UserVerified flag
			// PinUVAuth:         pinAuth,
			// PinUVAuthProtocol: ctap2token.PinProtoV1,
		})
		if err != nil {
			panic(err)
		}

		if !bytes.Equal(getAssertionResp.Credential.ID, mcpAuthData.AttestedCredentialData.CredentialID) {
			panic("CredentialID mismatch")
		}
		fmt.Printf("Found credential %x\n", getAssertionResp.Credential.ID)

		// Verify signature with the public key from MakeCredential
		pubX := new(big.Int)
		pubX.SetBytes(mcpAuthData.AttestedCredentialData.CredentialPublicKey.X)
		pubY := new(big.Int)
		pubY.SetBytes(mcpAuthData.AttestedCredentialData.CredentialPublicKey.Y)

		pubkey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     pubX,
			Y:     pubY,
		}

		hash := sha256.New()
		if _, err := hash.Write(getAssertionResp.AuthData); err != nil {
			panic(err)
		}
		if _, err := hash.Write(clientDataHash); err != nil {
			panic(err)
		}

		if !ecdsa.VerifyASN1(pubkey, hash.Sum(nil), getAssertionResp.Signature) {
			panic("invalid signature")
		}
		fmt.Println("Signature verified!")
	}
}
