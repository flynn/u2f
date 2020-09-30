package main

import (
	"fmt"
	"os"

	"github.com/flynn/u2f/cmd/cobracmd"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "fidoman",
	Short: "Manage FIDO security keys",
}

func init() {
	rootCmd.AddCommand(cobracmd.Reset())
	rootCmd.AddCommand(cobracmd.List())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
