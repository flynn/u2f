// Package u2fnfc implements the low-level FIDO U2F NFC protocol.
package u2fnfc

import (
	"fmt"
	"time"

	"github.com/sf1/go-card/smartcard"
)

var ctx *smartcard.Context

//GetContext returns the smartcard context singleton.
func GetContext() *smartcard.Context {
	if ctx == nil {
		ctx, _ = smartcard.EstablishContext()
	}
	return ctx
}

// A Device is used to store information about a U2F NFC card.
type Device struct {
	reader *smartcard.Reader
	card   *smartcard.Card
	uid    []byte
}

// Open initializes a communication channel with a U2F NFC card.
func Open() (*Device, error) {
	reader, error := GetContext().WaitForCardPresent()
	if error != nil {
		return nil, error
	}
	card, error := reader.Connect()
	if error != nil {
		return nil, error
	}
	command := smartcard.Command2(0xFF, 0xCA, 0x00, 0x00, 0x00)
	response, error := Transmit(card, command, 500*time.Millisecond)
	if error != nil {
		return nil, error
	}
	uid := []byte(response[:len(response)-2])
	command = smartcard.SelectCommand(0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01)
	response, error = Transmit(card, command, 500*time.Millisecond)
	if error != nil {
		return nil, error
	}
	if string(response[:4]) != "U2F_" {
		return nil, fmt.Errorf("u2fnfc: invalid applet response: %s", string(response[:len(response)-2]))
	}
	return &Device{
		reader: reader,
		card:   card,
		uid:    uid,
	}, nil
}

// Make sure the APDUs transmitted are valid.
func FixAPDU(data []byte) []byte {
	apdu := smartcard.CommandAPDU(data)
	if !apdu.IsValid() {
		if len(apdu) == 7 {
			return smartcard.Command1(data[0], data[1], data[2], data[3])
		} else {
			return smartcard.Command3(data[0], data[1], data[2], data[3], data[7:])
		}
	}
	return apdu
}

// Transmit is a wrapper around the TransmitAPDU function that adds timeout functionality.
// This way, failed communication does not lock up the program.
func Transmit(card *smartcard.Card, data []byte, timeout time.Duration) ([]byte, error) {
	c1 := make(chan []byte)
	c2 := make(chan error)
	go func(cmd []byte, card *smartcard.Card) {
		response, error := card.TransmitAPDU(cmd)
		if error != nil {
			c2 <- error
		} else {
			c1 <- response
		}
	}(data, card)
	select {
	case err := <-c2:
		return nil, err
	case ret := <-c1:
		return ret, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("u2fnfc: transaction timeout")
	}
}

// UID returns the unique ID of the current NFC card.
func (d *Device) UID() string {
	return fmt.Sprintf("%X", d.uid)
}

// Message sends a message to the U2F device.
func (d *Device) Message(data []byte) ([]byte, error) {
	data = FixAPDU(data)
	response, error := Transmit(d.card, data, 2*time.Second)
	if error != nil {
		return nil, error
	}
	ret := make([]byte, 0)
	for response[len(response)-2] == 0x61 && response[len(response)-1] == 0x00 {
		ret = append(ret, response[:len(response)-2]...)
		response, error = Transmit(d.card, smartcard.Command1(0x00, 0xC0, 0x00, 0x00), time.Second)
		if error != nil {
			return nil, error
		}
	}
	if response[len(response)-2] == 0x61 {
		ret = append(ret, response[:len(response)-2]...)
		response, error = Transmit(d.card, smartcard.Command2(0x00, 0xC0, 0x00, 0x00, response[len(response)-1]), time.Second)
		if error != nil {
			return nil, error
		}
	}
	ret = append(ret, response...)
	return ret, nil
}

// Close waits for the card to be removed.
func (d *Device) Close() {
	d.reader.WaitUntilCardRemoved()
}
