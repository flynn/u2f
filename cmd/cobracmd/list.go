package cobracmd

import (
	"fmt"

	"github.com/flynn/u2f/u2fhid"
	"github.com/spf13/cobra"
)

func List() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "list",
		Short:        "List connected security keys",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}

			devs, err := u2fhid.Devices()
			if err != nil {
				return err
			}

			for _, dev := range devs {
				d, err := u2fhid.Open(dev)
				if err != nil {
					return err
				}

				fmt.Printf("%s (ID: %04x:%04x) %s \n", dev.Path, dev.VendorID, dev.ProductID, dev.Product)
				if verbose {
					fmt.Printf("\tvendor: %s\n", dev.Manufacturer)
					fmt.Printf("\tversion: %d.%d\n", d.MajorDeviceVersion, d.MinorDeviceVersion)
					fmt.Printf("\tcapabilities:\n\t\tnmsg: %v\n\t\tcbor: %v\n\t\twink: %v\n",
						d.CababilityNMSG,
						d.CapabilityCBOR,
						d.CapabilityWink,
					)
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolP("verbose", "v", false, "display more informations")
	return cmd
}
