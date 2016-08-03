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
	devices, err := u2fhid.Devices()
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no U2F tokens found")
	}

	d := devices[0]
	log.Printf("manufacturer = %q, product = %q, vid = 0x%04x, pid = 0x%04x", d.Manufacturer, d.Product, d.ProductID, d.VendorID)

	dev, err := u2fhid.Open(d)
	if err != nil {
		log.Fatal(err)
	}
	t := u2ftoken.NewToken(dev)

	version, err := t.Version()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("version:", version)

	challenge := make([]byte, 32)
	app := make([]byte, 32)
	io.ReadFull(rand.Reader, challenge)
	io.ReadFull(rand.Reader, app)

	var res []byte
	log.Println("registering, provide user presence")
	for {
		res, err = t.Register(u2ftoken.RegisterRequest{Challenge: challenge, Application: app})
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
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

	dev.Close()

	log.Println("reconnecting to device in 3 seconds...")
	time.Sleep(3 * time.Second)

	devices, err = u2fhid.Devices()
	if err != nil {
		log.Fatal(err)
	}
	d = devices[0]
	dev, err = u2fhid.Open(d)
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
	log.Println("authenticating, provide user presence")
	for {
		res, err := t.Authenticate(req)
		if err == u2ftoken.ErrPresenceRequired {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if err != nil {
			log.Fatal(err)
		}
		log.Printf("counter = %d, signature = %x", res.Counter, res.Signature)
		break
	}

	if dev.CapabilityWink {
		log.Println("testing wink in 2s...")
		time.Sleep(2 * time.Second)
		if err := dev.Wink(); err != nil {
			log.Fatal(err)
		}
		time.Sleep(2 * time.Second)
	} else {
		log.Println("no wink capability")
	}
}
