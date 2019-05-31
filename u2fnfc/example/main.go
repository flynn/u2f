package main

import (
	"crypto/rand"
	"io"
	"log"
	"time"

	"github.com/flynn/u2f/u2fnfc"
	"github.com/flynn/u2f/u2ftoken"
)

func main() {
	log.Println("waiting for card...")
	dev, err := u2fnfc.Open()
	if err != nil {
		log.Fatal(err)
	}
	t := u2ftoken.NewToken(dev)

	version, err := t.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("version:", version)
	log.Println("uid:", dev.UID())

	challenge := make([]byte, 32)
	app := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	io.ReadFull(rand.Reader, app)

	var res []byte
	log.Println("registering")
	for {
		res, err = t.Register(u2ftoken.RegisterRequest{Challenge: challenge, Application: app})
		if err != nil {
			log.Fatal(err)
		}
		break
	}

	log.Printf("registered: %x", res)
	res = res[66:]
	khLen := int(res[0])
	res = res[1:]
	keyHandle := res[:khLen]
	log.Printf("key handle: %x", keyHandle)

	log.Println("please remove card")
	dev.Close()

	log.Println("reconnecting to device in 3 seconds...")
	time.Sleep(3 * time.Second)

	log.Println("waiting for card...")
	dev, err = u2fnfc.Open()
	if err != nil {
		log.Fatal(err)
	}
	t = u2ftoken.NewToken(dev)

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
	log.Println("authenticating")
	for {
		res, err := t.Authenticate(req)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}
}
