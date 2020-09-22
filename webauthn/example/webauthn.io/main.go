package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/webauthn"
)

func main() {
	var username string
	var action string
	flag.StringVar(&username, "u", "", "the username to authenticate with")
	flag.StringVar(&action, "a", "", "the webauthn action (authenticate or register)")
	flag.Parse()

	if username == "" {
		flag.Usage()
		fmt.Println("-u is required")
		os.Exit(1)
	}
	if action == "" {
		flag.Usage()
		fmt.Println("-a is required")
		os.Exit(1)
	}

	host := "https://webauthn.io"

	devices, err := u2fhid.Devices()
	if err != nil {
		panic(err)
	}

	if len(devices) == 0 {
		panic("no HID devices found")
	}

	d := devices[0]

	dev, err := u2fhid.Open(d)
	if err != nil {
		panic(err)
	}

	t, err := webauthn.NewToken(dev, pin.NewInteractiveHandler(ctap2token.NewToken(dev)))
	if err != nil {
		panic(err)
	}

	switch action {
	case "register":
		err = register(t, username, host)
	case "authenticate":
		err = authenticate(t, username, host)
	default:
		panic(fmt.Sprintf("invalid action: %s", action))
	}

	if err != nil {
		panic(err)
	}
}

func register(t webauthn.Token, username, host string) error {
	c := &http.Client{}

	httpResp, err := c.Get(fmt.Sprintf("%s/makeCredential/%s?attType=direct&authType=&userVerification=preferred&residentKeyRequirement=false&txAuthExtension=", host, username))
	if err != nil {
		return err
	}

	dump, err := httputil.DumpResponse(httpResp, true)
	if err != nil {
		return err
	}
	fmt.Printf("response: %s\n", dump)
	if httpResp.StatusCode != 200 {
		return errors.New("non 200 server response")
	}

	webauthnReq := &struct {
		PublicKey *webauthn.RegisterRequest `json:"publicKey"`
	}{}

	err = json.NewDecoder(httpResp.Body).Decode(webauthnReq)
	if err != nil {
		return err
	}

	fmt.Printf("Webauthn registration request for %q on %q. Confirm presence on authenticator when it will blink...\n", username, host)
	webauthnResp, err := t.Register(host, webauthnReq.PublicKey)
	if err != nil {
		return err
	}

	rd, _ := json.MarshalIndent(webauthnResp, "", "  ")
	fmt.Printf("authenticator response: %s\n", rd)

	attObjBytes, err := webauthnResp.Response.AttestationObject.CBOREncode(false)
	if err != nil {
		return err
	}

	registerHttpResponse := map[string]interface{}{
		"id":    base64.RawURLEncoding.EncodeToString(webauthnResp.ID),
		"rawId": base64.RawURLEncoding.EncodeToString(webauthnResp.ID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attObjBytes),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(webauthnResp.Response.ClientDataJSON),
		},
	}

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(registerHttpResponse); err != nil {
		return err
	}

	httpPostReq, err := http.NewRequest("POST", fmt.Sprintf("%s/makeCredential", host), buf)
	if err != nil {
		return err
	}

	for _, c := range httpResp.Cookies() {
		httpPostReq.AddCookie(c)
	}

	httpPostResp, err := c.Do(httpPostReq)
	if err != nil {
		return err
	}

	dump, err = httputil.DumpResponse(httpPostResp, true)
	if err != nil {
		return err
	}
	fmt.Printf("response: %s\n", dump)

	return nil
}

func authenticate(t webauthn.Token, username, host string) error {
	c := &http.Client{}
	httpResp, err := c.Get(fmt.Sprintf("%s/assertion/%s?userVer=discouraged&txAuthExtension=", host, username))
	if err != nil {
		return err
	}

	d, err := httputil.DumpResponse(httpResp, true)
	if err != nil {
		return err
	}
	fmt.Printf("response: %s\n", d)

	if httpResp.StatusCode != 200 {
		return errors.New("non 200 server response, maybe register first ?")
	}

	authReq := &struct {
		PublicKey *webauthn.AuthenticateRequest `json:"publicKey"`
	}{}

	err = json.NewDecoder(httpResp.Body).Decode(authReq)
	if err != nil {
		return err
	}

	fmt.Printf("Webauthn authentication request for %q on %q. Confirm presence on authenticator when it will blink...\n", username, host)
	webauthnResp, err := t.Authenticate(host, authReq.PublicKey)
	if err != nil {
		return err
	}

	rd, _ := json.MarshalIndent(webauthnResp, "", "  ")
	fmt.Printf("authenticator response: %s\n", rd)

	httpAuthResp := map[string]interface{}{
		"id":    base64.RawURLEncoding.EncodeToString(webauthnResp.ID),
		"rawId": base64.RawURLEncoding.EncodeToString(webauthnResp.ID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(webauthnResp.Response.AuthenticatorData),
			"signature":         base64.RawURLEncoding.EncodeToString(webauthnResp.Response.Signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(webauthnResp.Response.UserHandle),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(webauthnResp.Response.ClientDataJSON),
		},
	}

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(httpAuthResp); err != nil {
		return err
	}

	httpPostReq, err := http.NewRequest("POST", fmt.Sprintf("%s/assertion", host), buf)
	if err != nil {
		return err
	}

	for _, c := range httpResp.Cookies() {
		httpPostReq.AddCookie(c)
	}

	httpPostResp, err := c.Do(httpPostReq)
	if err != nil {
		return err
	}

	d, err = httputil.DumpResponse(httpPostResp, true)
	if err != nil {
		return err
	}

	fmt.Printf("response: %s\n", d)
	return nil
}
