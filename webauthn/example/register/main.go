package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/ctap2token/pin"
	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/webauthn"
)

func main() {
	var host string
	var username string

	flag.StringVar(&username, "u", "", "the username to authenticate with")
	flag.StringVar(&host, "s", "https://webauthn.io", "the target webauthn server")
	flag.Parse()

	if username == "" {
		flag.Usage()
		panic("username is required")
	}

	if host == "" {
		flag.Usage()
		panic("host is required")
	}

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

	c := &http.Client{}

	httpResp, err := c.Get(fmt.Sprintf("%s/makeCredential/%s?attType=none&authType=&userVerification=preferred&residentKeyRequirement=false&txAuthExtension=", host, username))
	if err != nil {
		panic(err)
	}

	dump, err := httputil.DumpResponse(httpResp, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("response: %s\n", dump)
	if httpResp.StatusCode != 200 {
		panic("non 200 server response")
	}

	webauthnReq := &webauthn.RegisterRequest{}
	err = json.NewDecoder(httpResp.Body).Decode(webauthnReq)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Webauthn registration request for %q on %q. Confirm presence on authenticator when it will blink...\n", username, host)
	webauthnResp, err := t.Register(host, webauthnReq)
	if err != nil {
		panic(err)
	}

	rd, _ := json.MarshalIndent(webauthnResp, "", "  ")
	fmt.Printf("%s\n", rd)

	buf := bytes.NewBuffer(nil)
	if err := json.NewEncoder(buf).Encode(webauthnResp); err != nil {
		panic(err)
	}

	httpPostReq, err := http.NewRequest("POST", fmt.Sprintf("%s/makeCredential", host), buf)
	if err != nil {
		panic(err)
	}

	for _, c := range httpResp.Cookies() {
		httpPostReq.AddCookie(c)
	}

	httpPostResp, err := c.Do(httpPostReq)
	if err != nil {
		panic(err)
	}

	dump, err = httputil.DumpResponse(httpPostResp, true)
	if err != nil {
		panic(err)
	}
	fmt.Printf("response: %s\n", dump)
}
