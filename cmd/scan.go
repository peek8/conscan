/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, August 19th 2025, 11:38:34 am
 * Author: Md. Asraful Haque
 *
 */

package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/scanner"
)

var scanUsage = "use conscan scan imageTag"

var formatFlagVar string
var outputFlagVar string
var scannersFlagVar []string

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
		opts := models.ScanOptions{
			Format:     models.OutputFormat(formatFlagVar),
			OutputFile: outputFlagVar,
		}
		opts.SetScanners(scannersFlagVar)

		msg, ok := opts.Validate()
		if !ok {
			log.Fatalf("%s", msg)
		}

		scanner.ScanImage(args[0], opts)
	},
}

func init() {
	// Here you will define your flags and configuration settings.
	scanCmd.PersistentFlags().StringVarP(&formatFlagVar, "format", "f", "table", "Format of the scanning report")
	scanCmd.PersistentFlags().StringVarP(&outputFlagVar, "output", "o", "", "Output File name (optional)")
	scanCmd.PersistentFlags().StringSliceVar(&scannersFlagVar,
		"scanners",
		[]string{string(models.ScannerAll)},
		fmt.Sprintf("Comma-separated list of what type of scans to be performed (allowed values: %s).\nBy default, Every scan is performed. Except for 'table format', \"Scanning\" Packages is  excluded for the sake of brevity while the report is not written to Console", models.SupportedScanners))
}
