/*
Copyright © 2025 peek8.io
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"peek8.io/conscan/pkg/scanner"
)

var scanUsage = "use conscan scan imageTag"

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scans vulnerabilities in a container image",
	Long:  `Scans vulnerabilities in a container image`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Image tag missing")
			fmt.Println(scanUsage)
			os.Exit(1)
		}

		fmt.Printf("Scanning Image %s...", args[0])
		scanner.ScanVuln(args[0])
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// vulnCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// vulnCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
