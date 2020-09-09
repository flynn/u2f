package main

import (
	"fmt"

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
		fmt.Printf("%#v\n", infos)
	}
}
