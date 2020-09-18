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

	for _, d := range devices {
		dev, err := u2fhid.Open(d)
		if err != nil {
			panic(err)
		}

		t, err := webauthn.NewToken(dev, pin.NewInteractiveHandler(ctap2token.NewToken(dev)))
		if err != nil {
			panic(err)
		}

		c := &http.Client{}
		// localhost:9005 runs a server from https://github.com/duo-labs/webauthn.io
		httpResp, err := c.Get(fmt.Sprintf("%s/assertion/%s?userVer=discouraged&txAuthExtension=", host, username))
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

		authReq := &webauthn.AuthenticateRequest{}
		err = json.NewDecoder(httpResp.Body).Decode(authReq)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Webauthn authentication request for %q on %q. Confirm presence on authenticator when it will blink...\n", username, host)
		authResp, err := t.Authenticate(host, authReq)
		if err != nil {
			panic(err)
		}

		rd, _ := json.MarshalIndent(authResp, "", "  ")
		fmt.Printf("%s\n", rd)

		buf := bytes.NewBuffer(nil)
		if err := json.NewEncoder(buf).Encode(authResp); err != nil {
			panic(err)
		}

		httpPostReq, err := http.NewRequest("POST", fmt.Sprintf("%s/assertion", host), buf)
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

		d, err = httputil.DumpResponse(httpPostResp, true)
		if err != nil {
			panic(err)
		}
		fmt.Printf("response: %s\n", d)
	}
}
