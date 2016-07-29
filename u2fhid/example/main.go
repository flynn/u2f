package main

import (
	"bytes"
	"log"
	"strings"

	"github.com/flynn/u2f/u2fhid"
)

func main() {
	msg := []byte(strings.Repeat("echo", 100))
	for _, d := range u2fhid.Devices() {
		dev, err := u2fhid.Open(d)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("opened", d.Path)
		res, err := dev.Ping([]byte(msg))
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(res, msg) {
			log.Fatalf("expected %x, got %x", msg, res)
		}
		log.Println("successfully pinged", d.Path)
	}
}
