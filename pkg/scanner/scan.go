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
	"slices"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/samber/lo"
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

const (
	FormatJson  = "json"
	FormatTable = "table"
)

type ScanTask struct {
	scannerType models.ScannerType
	name        string
	scanFunc    func(string) scannerFunc
}

type scannerFunc func(res *models.ScanResult) error

func ScanImage(imageTag string, opts models.ScanOptions) {
	tasks := getScanTasks(opts)

	result := &models.ScanResult{}
	out := os.Stderr

	tickColor := color.New(color.FgHiGreen).Sprint("✔")
	for _, st := range tasks {
		spinner := log.StartSprinner(st.name, log.MagnifyGlasses, out)
		scanner := st.scanFunc(imageTag)
		err := scanner(result)

		spinner.Stop()
		if err != nil {
			utils.ExitOnError(err)
		}

		fmt.Fprintf(io.Writer(out), "[%s] %s finished\n", tickColor, st.name)
	}

	// we get the image metadata from trivy report, so if vuln and/or secret scanning not selected we will miss those
	// metadata, so if trivyReport is nil, run the secret scanning to get the metadata
	if result.TrivyResult == nil {
		secScanner := scannersMap()[models.ScannerSecret].scanFunc(imageTag)
		err := secScanner(result)
		if err != nil {
			utils.ExitOnError(err)
		}
	}

	// Now generating Report
	spinner := log.StartSprinner("Generate Report", spinner.CharSets[14], out)
	ra := report.NewReportAggregator(result, opts)
	agReport := ra.AggreagateReport()
	spinner.Stop()
	fmt.Fprintf(io.Writer(out), "[✔] %s finished\n", "Generate Report")

	err := report.Write(context.Background(), *agReport, opts)

	if err != nil {
		utils.ExitOnError(err)
	}

}

func getScanTasks(opts models.ScanOptions) []ScanTask {
	sMap := scannersMap()

	if slices.Contains(opts.Scanners, models.ScannerAll) {
		return scanners()
	}

	return lo.Map(opts.Scanners, func(s models.ScannerType, _ int) ScanTask {
		return sMap[s]
	})
}

func scannersMap() map[models.ScannerType]ScanTask {
	return lo.KeyBy(scanners(), func(s ScanTask) models.ScannerType {
		return s.scannerType
	})
}

func scanners() []ScanTask {
	return []ScanTask{
		{
			scannerType: models.ScannerVulnerability,
			name:        "Scan Vulnerabilities",
			scanFunc: func(imageTag string) scannerFunc {
				return func(res *models.ScanResult) error {
					// scan vulnerability that also include secrets from trivy
					res.TrivyResult, res.GrypeResult = ScanVuln(imageTag)
					return nil
				}
			},
		},
		{
			scannerType: models.ScannerSecret,
			name:        "Scan Secrets",
			scanFunc: func(imageTag string) scannerFunc {
				return func(res *models.ScanResult) error {
					report := scanSecrets(imageTag)

					if res.TrivyResult == nil {
						res.TrivyResult = &report
					} else {
						res.TrivyResult.Results = append(res.TrivyResult.Results, report.Results...)
					}

					return nil
				}
			},
		},
		{
			scannerType: models.ScannerPackage,
			name:        "Scan Packages",
			scanFunc: func(imageTag string) scannerFunc {
				return func(res *models.ScanResult) error {
					res.SyftySBOMs = SyftScanForSboms(imageTag)
					return nil
				}
			},
		},
		{
			scannerType: models.ScannerStorage,
			name:        "Scan Storages",
			scanFunc: func(imageTag string) scannerFunc {
				return func(res *models.ScanResult) error {
					res.StorageAnalysis = ScanForStorage(imageTag)
					return nil
				}
			},
		},
		{
			scannerType: models.ScannerCIS,
			name:        "Scan CIS Benchmark",
			scanFunc: func(imageTag string) scannerFunc {
				return func(res *models.ScanResult) error {
					res.CISScans = DockleScanForCIS(imageTag)
					return nil
				}
			},
		},
	}
}
