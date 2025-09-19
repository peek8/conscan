/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, August 19th 2025, 6:15:04 pm
 * Author: Md. Asraful Haque
 *
 */

// Package scanner scans the container image for vulnerabilities, securities, licenses etc
package scanner

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"peek8.io/conscan/pkg/log"
	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/report"
	"peek8.io/conscan/pkg/utils"
)

// Trivy Scanner Flag
const (
	TrivyScannerVulnFlag      = "vuln"
	TrivyScannerMisConfigFlag = "misconfig"
	TrivyScannerSecretFlag    = "secret"
	TrivyScannerLicenseFlag   = "license"
)

// Trivy output format
const (
	FormatJson  = "json"
	FormatTable = "table"
)

func ScanImage(imageTag string, opts models.ScanOptions) {
	tasks := []ScanTask{
		{
			name: "Scan Vulnerabilities and Secrets",
			scanFunc: func(res *models.ScanResult) error {
				// scan vulnerability that also include secrets from trivy
				res.TrivyResult, res.GrypeResult = ScanVuln(imageTag)
				return nil
			},
		},
		{
			name: "Scan Packages",
			scanFunc: func(res *models.ScanResult) error {
				res.SyftySBOMs = SyftScanForSboms(imageTag)
				return nil
			},
		},
		{
			name: "Scan Storages",
			scanFunc: func(res *models.ScanResult) error {
				res.StorageAnalysis = ScanForStorage(imageTag)
				return nil
			},
		},
		{
			name: "Scan CIS Benchmark",
			scanFunc: func(res *models.ScanResult) error {
				res.CISScans = DockleScanForCIS(imageTag)
				return nil
			},
		},
	}

	result := &models.ScanResult{}
	out := os.Stderr

	tickColor := color.New(color.FgHiGreen).Sprint("✔")
	for _, st := range tasks {
		spinner := log.StartSprinner(st.name, log.MagnifyGlasses, out)
		err := st.scanFunc(result)

		spinner.Stop()
		if err != nil {
			utils.ExitOnError(err)
		}

		fmt.Fprintf(io.Writer(out), "[%s] %s finished\n", tickColor, st.name)
	}

	// Now generating Report
	spinner := log.StartSprinner("Generate Report", spinner.CharSets[14], out)
	ra := report.NewReportAggregator(result)
	agReport := ra.AggreagateReport()
	spinner.Stop()
	fmt.Fprintf(io.Writer(out), "[✔] %s finished\n", "Generate Report")

	err := report.Write(context.Background(), *agReport, opts)

	if err != nil {
		utils.ExitOnError(err)
	}

}

type ScanTask struct {
	name     string
	scanFunc func(res *models.ScanResult) error
}
