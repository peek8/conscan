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

	"github.com/peek8/conscan/pkg/models"
	"github.com/peek8/conscan/pkg/scanner"
	"github.com/peek8/conscan/pkg/utils"
	"github.com/spf13/cobra"
)

const (
	formatFlag = "format"
	uploadFlag = "upload"
)

var scanUsage = `Scan a container image for vulnerabilities, exposed secrets, inefficient file storage, installed packages and check CIS(Center for Internet Security) Benchmarks.

Examples:	
# Scan a container image locally available
$ conscan scan yourimage:tag          // uses the Podman/Docker daemon for local images

# Scan container images from registry eg. dockerhub
$ conscan scan docker.io/yourimage:tag

# or from github image repo
$ conscan scan ghcr.io/yourimage:tag

# By default the scan report will be in Table format that is more convenient for the Console output. 
# If you want the report in json format, you can use
$ conscan scan --format json -o report.json yourimage:tag # the report will be saved to report.json

# Similary to save in html format:
$ conscan scan --format html -o report.html yourimage:tag

# By default, conscan will scan everything. If you are interested for specific scan report, eg only vulnerabilities and exposed secrets you can use like:
$ conscan scan --scanners=vuln,secret yourimage:tag
`

var formatFlagVar string
var outputFlagVar string
var uploadFlagVar string
var scannersFlagVar []string

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scans a container image",
	Long:  scanUsage,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			_ = cmd.Help()
			utils.ExitOnError(fmt.Errorf("Image tag missing, use `conscan scan yourimage:tag`"))
		}
		opts := models.ScanOptions{
			Format:     models.OutputFormat(formatFlagVar),
			OutputFile: outputFlagVar,
			UploadURL:  uploadFlagVar,
			// check if the upload flag was used by user
			Upload: cmd.Flags().Changed(uploadFlag),
		}
		opts.SetScanners(scannersFlagVar)

		// if the command is to upload then the default format is json if not provided by user
		if cmd.Flags().Changed(uploadFlag) && !cmd.Flags().Changed(formatFlag) {
			opts.Format = models.FormatJson
		}

		msg, ok := opts.Validate()
		if !ok {
			log.Fatalf("%s", msg)
		}

		scanner.ScanImage(args[0], opts)
	},
}

func init() {
	// Here you will define your flags and configuration settings.
	scanCmd.PersistentFlags().StringVarP(&formatFlagVar, formatFlag, "f", "table", "Format of the scanning report")
	scanCmd.PersistentFlags().StringVarP(&outputFlagVar, "output", "o", "", "Output File name (optional)")
	scanCmd.PersistentFlags().StringVarP(&uploadFlagVar, uploadFlag, "u", "", "Upload API Endpoint (optional)")
	scanCmd.PersistentFlags().StringSliceVar(&scannersFlagVar,
		"scanners",
		[]string{string(models.ScannerAll)},
		fmt.Sprintf("Comma-separated list of what type of scans to be performed (allowed values: %s).\nBy default, Every scan is performed. Except for 'table format', \"Scanning\" Packages is  excluded for the sake of brevity while the report is not written to Console", models.SupportedScanners))
}
