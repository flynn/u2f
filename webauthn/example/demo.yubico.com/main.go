package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/webauthn"
)

func main() {
	var action string
	var session string
	flag.StringVar(&action, "a", "", "the webauthn action (authenticate or register)")
	flag.StringVar(&session, "s", "", "the session cookie (given by register, provided to authenticate")
	flag.Parse()

	if action == "" {
		flag.Usage()
		fmt.Println("-a is required")
		os.Exit(1)
	}

	host := "https://demo.yubico.com"

	t := webauthn.New(webauthn.WithCTAP2PinHandler(pin.NewInteractiveHandler()))

	var err error
	switch action {
	case "register":
		err = register(t, host)
	case "authenticate":
		if session == "" {
			flag.Usage()
			fmt.Println("-s is required")
			os.Exit(1)
		}

		err = authenticate(t, host, session)
	default:
		panic(fmt.Sprintf("invalid action: %s", action))
	}

	if err != nil {
		panic(err)
	}
}

func register(t *webauthn.WebAuthn, host string) error {
	c := &http.Client{}
	reqBody := bytes.NewBuffer([]byte(`{"userVerification":"preferred"}`))
	httpResp, err := c.Post(fmt.Sprintf("%s/api/v1/simple/webauthn/register-begin", host), "application/json", reqBody)
	if err != nil {
		return err
	}

	d, err := httputil.DumpResponse(httpResp, true)
	if err != nil {
		return err
	}
	fmt.Printf("response: %s\n", d)

	if httpResp.StatusCode != 200 {
		return errors.New("non 200 server response")
	}

	respData := &struct {
		Data struct {
			PublicKey   *webauthn.RegisterRequest `json:"publicKey"`
			DisplayName string                    `json:"displayName"`
			Icon        string                    `json:"icon"`
			RequestID   string                    `json:"requestId"`
			Username    string                    `json:"username"`
		} `json:"data"`
	}{}

	err = json.NewDecoder(httpResp.Body).Decode(respData)
	if err != nil {
		return err
	}

	fmt.Printf("WebAuthn registration request for %q on %q. Confirm presence on authenticator when it will blink...\n", respData.Data.Username, host)
	webauthnResp, err := t.Register(context.Background(), host, respData.Data.PublicKey)
	if err != nil {
		return err
	}

	rd, _ := json.MarshalIndent(webauthnResp, "", "  ")
	fmt.Printf("authenticator response: %s\n", rd)

	attObjBytes, err := webauthnResp.Response.AttestationObject.CBOREncode(true)
	if err != nil {
		return err
	}

	registerHttpResponse := map[string]interface{}{
		"requestId":   respData.Data.RequestID,
		"username":    respData.Data.Username,
		"displayName": respData.Data.DisplayName,
		"attestation": map[string]interface{}{
			"attestationObject": attObjBytes,
			"clientDataJSON":    webauthnResp.Response.ClientDataJSON,
		},
	}

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(registerHttpResponse); err != nil {
		return err
	}

	httpPostReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/simple/webauthn/register-finish", host), buf)
	if err != nil {
		return err
	}

	httpPostReq.Header.Add("Content-Type", "application/json")
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
	fmt.Printf("session cookie value:\n%s\n", httpPostResp.Cookies()[0].Value)
	return nil
}

func authenticate(t *webauthn.WebAuthn, host, session string) error {
	c := &http.Client{}
	reqBody := bytes.NewBuffer([]byte(`{"userVerification":"preferred"}`))

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/simple/webauthn/authenticate-begin", host), reqBody)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:  "demo_website_session",
		Value: session,
	})

	httpResp, err := c.Do(req)
	if err != nil {
		panic(err)
	}

	d, err := httputil.DumpResponse(httpResp, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("response: %s\n", d)

	if httpResp.StatusCode != 200 {
		panic("non 200 server response, maybe register first ?")
	}

	respData := &struct {
		Data struct {
			PublicKey *webauthn.AuthenticateRequest `json:"publicKey"`
			RequestID string                        `json:"requestId"`
			Username  string                        `json:"username"`
		} `json:"data"`
	}{}

	err = json.NewDecoder(httpResp.Body).Decode(respData)
	if err != nil {
		panic(err)
	}

	fmt.Printf("WebAuthn authentication request for %q on %q. Confirm presence on authenticator when it will blink...\n", respData.Data.Username, host)
	webauthnResp, err := t.Authenticate(context.Background(), host, respData.Data.PublicKey)
	if err != nil {
		panic(err)
	}

	rd, _ := json.MarshalIndent(webauthnResp, "", "  ")
	fmt.Printf("authenticator response: %s\n", rd)

	registerHttpResponse := map[string]interface{}{
		"requestId": respData.Data.RequestID,
		"assertion": map[string]interface{}{
			"authenticatorData": webauthnResp.Response.AuthenticatorData,
			"clientDataJSON":    webauthnResp.Response.ClientDataJSON,
			"credentialId":      webauthnResp.ID,
			"signature":         webauthnResp.Response.Signature,
		},
	}

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(registerHttpResponse); err != nil {
		panic(err)
	}

	httpPostReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/simple/webauthn/authenticate-finish", host), buf)
	if err != nil {
		panic(err)
	}

	httpPostReq.Header.Add("Content-Type", "application/json")
	for _, c := range httpResp.Cookies() {
		httpPostReq.AddCookie(c)
	}

	httpPostResp, err := c.Do(httpPostReq)
	if err != nil {
		panic(err)
	}

	d, err = httputil.DumpResponse(httpPostResp, true)
	if err != nil {
		panic(err)
	}

	fmt.Printf("response: %s\n", d)
	return nil
}
