package main

import (
	"crypto/rand"
	"io"
	"log"
	"time"

	"github.com/flynn/u2f/u2fhid"
	"github.com/flynn/u2f/u2ftoken"
)

func main() {
	dev, err := u2fhid.Open(u2fhid.Devices()[0])
	if err != nil {
		log.Fatal(err)
	}
	t := u2ftoken.NewToken(dev)

	challenge := make([]byte, 32)
	app := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	io.ReadFull(rand.Reader, app)

	res, err := t.Register(u2ftoken.RegisterRequest{Challenge: challenge, Application: app})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("registered: %x", res)

	version, err := t.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("version:", version)

	res = res[66:]
	khLen := int(res[0])
	res = res[1:]
	keyHandle := res[:khLen]
	log.Printf("key handle: %x", keyHandle)

	io.ReadFull(rand.Reader, challenge)
	req := u2ftoken.AuthenticateRequest{
		Challenge:   challenge,
		Application: app,
		KeyHandle:   keyHandle,
	}
	if err := t.CheckAuthenticate(req); err != nil {
		log.Fatal(err)
	}

	io.ReadFull(rand.Reader, challenge)
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			log.Println("user presence required, retrying in one second")
			time.Sleep(time.Second)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}
}
