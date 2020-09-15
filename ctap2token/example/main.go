package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/flynn/u2f/ctap2token"
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
			panic(err)
		}
		fmt.Printf("Token infos:\n%#v\n", infos)

		// // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#gettingSharedSecret
		// fmt.Println("Retrieving key agreement from authenticator")
		// cp1, err := token.ClientPIN(&ctap2token.ClientPINRequest{
		// 	PinProtocol: ctap2token.PinProtoV1,
		// 	SubCommand:  ctap2token.GetKeyAgreement,
		// })
		// if err != nil {
		// 	panic(err)
		// }

		// fmt.Println("Generating platform key pair")
		// b, bGX, bGY, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		// if err != nil {
		// 	panic(err)
		// }

		// aG := cp1.KeyAgreement
		// aGX := new(big.Int)
		// aGX.SetBytes(aG.X)

		// aGY := new(big.Int)
		// aGY.SetBytes(aG.Y)

		// rX, _ := elliptic.P256().ScalarMult(aGX, aGY, b)

		// h := sha256.New()
		// _, err = h.Write(rX.Bytes())
		// if err != nil {
		// 	panic(err)
		// }

		// sharedSecret := h.Sum(nil)
		// fmt.Println("Generated shared secret")

		// reader := bufio.NewReader(os.Stdin)
		// fmt.Print("Enter PIN: ")
		// userPIN, _ := reader.ReadString('\n')

		// h.Reset()
		// _, err = h.Write([]byte(strings.TrimSpace(userPIN)))
		// if err != nil {
		// 	panic(err)
		// }

		// pinHash := h.Sum(nil)
		// pinHash = pinHash[:aes.BlockSize]

		// pinHashEnc := make([]byte, aes.BlockSize)
		// c, err := aes.NewCipher(sharedSecret)
		// if err != nil {
		// 	panic(err)
		// }
		// iv := make([]byte, aes.BlockSize)
		// cbcEnc := cipher.NewCBCEncrypter(c, iv)
		// cbcEnc.CryptBlocks(pinHashEnc, pinHash)
		// fmt.Println("Encrypted user PIN using shared secret")

		// pinResp, err := token.ClientPIN(&ctap2token.ClientPINRequest{
		// 	SubCommand: ctap2token.GetPINUvAuthTokenUsingPIN,
		// 	KeyAgreement: &ctap2token.COSEKey{
		// 		X:       bGX.Bytes(),
		// 		Y:       bGY.Bytes(),
		// 		KeyType: ctap2token.EC2,
		// 		Curve:   ctap2token.P256,
		// 		Alg:     ctap2token.ECDHES_HKDF256,
		// 	},
		// 	PinHashEnc:  pinHashEnc,
		// 	PinProtocol: ctap2token.PinProtoV1,
		// })
		// if err != nil {
		// 	panic(err)
		// }

		// // Decrypt pinToken using shared secret
		// pinHashDec := make([]byte, aes.BlockSize)
		// cbcDec := cipher.NewCBCDecrypter(c, iv)
		// cbcDec.CryptBlocks(pinHashDec, pinResp.PinToken)
		// fmt.Println("Decrypted authenticator pinToken")

		clientDataHash := make([]byte, 32)
		if _, err := rand.Read(clientDataHash); err != nil {
			panic(err)
		}

		userID := make([]byte, 32)
		if _, err := rand.Read(userID); err != nil {
			panic(err)
		}

		// mac := hmac.New(sha256.New, pinHashDec)
		// _, err = mac.Write(clientDataHash)
		// if err != nil {
		// 	panic(err)
		// }

		// pinAuth := mac.Sum(nil)
		// pinAuth = pinAuth[:16]
		// fmt.Println("Signed clientData with pinToken")

		fmt.Println("Sending makeCredential request, please press authenticator button...")
		resp, err := token.MakeCredential(&ctap2token.MakeCredentialRequest{
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
			Options: ctap2token.AuthenticatorOptions{
				"clientPin": false,
				"uv":        false,
			},
			// PinUVAuth:         pinAuth,
			// PinUVAuthProtocol: ctap2token.PinProtoV1,
		})
		if err != nil {
			panic(err)
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
