package cobracmd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/flynn/u2f/ctap2token"
	"github.com/flynn/u2f/u2fhid"
	"github.com/spf13/cobra"
)

func Reset() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "reset",
		Short:        "Restore a device to factory settings",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			devicePath, err := cmd.Flags().GetString("device")
			if err != nil {
				return err
			}

			devices, err := u2fhid.Devices()
			if err != nil {
				return err
			}

			if len(devices) == 0 {
				return errors.New("no U2F device detected")
			}

			dev := devices[0]
			if len(devices) > 1 {
				if devicePath == "" {
					fmt.Println("Multiple devices found. Select the one to reset using the -d flag:")
					for _, d := range devices {
						fmt.Printf("  - %s: %s %s\n", d.Path, d.Manufacturer, d.Product)
					}
					return nil
				} else {
					var found bool
					for _, d := range devices {
						if d.Path == devicePath {
							dev = d
							found = true
							break
						}
					}
					if !found {
						return fmt.Errorf("cannot find U2F device at %s", devicePath)
					}
				}
			}

			u2fdev, err := u2fhid.Open(dev)
			if err != nil {
				return err
			}

			if !u2fdev.CapabilityCBOR {
				return errors.New("device doesn't support reset command")
			}

			if !userConfirm("WARNING! This will delete all FIDO credentials, including FIDO U2F credentials, and restore factory settings. Proceed?") {
				return errors.New("operation canceled")
			}

			t := ctap2token.NewToken(u2fdev)
			infos, err := t.GetInfo()
			if err != nil {
				return err
			}
			u2fdev.Close()

			fmt.Println("Remove and re-insert your device to perform the reset...")
			waitForDevice(infos.AAGUID, false)
			fmt.Println("Device removed, now you can re-insert it...")
			t = waitForDevice(infos.AAGUID, true)
			fmt.Println("Confirm reset by pressing the user presence button...")
			if err := t.Reset(); err != nil {
				return err
			}
			fmt.Println("done!")
			return nil
		},
	}

	cmd.Flags().StringP("device", "d", "", "path to the HID device")
	return cmd
}

func userConfirm(prompt string) bool {
	var s string

	fmt.Printf("%s (y/N): ", prompt)
	_, err := fmt.Scan(&s)
	if err != nil {
		return false
	}

	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	if s == "y" || s == "yes" {
		return true
	}
	return false
}

func waitForDevice(id []byte, plugged bool) *ctap2token.Token {
	found := false
	for {
		found = false
		devices, _ := u2fhid.Devices()
		for _, d := range devices {
			u2fdev, err := u2fhid.Open(d)
			if err != nil {
				continue
			}

			t := ctap2token.NewToken(u2fdev)
			infos, err := t.GetInfo()
			if err != nil {
				continue
			}

			if bytes.Equal(infos.AAGUID, id) {
				found = true
				if plugged {
					return t
				}
			}
		}

		if !found && !plugged {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}
}
