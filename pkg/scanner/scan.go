/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, August 19th 2025, 6:15:04 pm
 * Author: Md. Asraful Haque
 *
 * -----
 * Last Modified: Tuesday, 2nd September 2025 6:47:03 pm
 * Modified By: Md. Asraful Haque
 * -----
 */

// Package scanner scans the container image for vulnerabilities, securities, licenses etc
package scanner

import (
	"context"
	"log"

	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/report"
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
	// scan vulnerability that also include secrets from trivy
	result := ScanVuln(imageTag)

	// scan sboms
	result.SyftySBOMs = SyftScanForSboms(imageTag)

	ra := NewReportAggregator(result)
	agReport := ra.AggreagateReport()

	err := report.Write(context.Background(), *agReport, opts)

	if err != nil {
		log.Fatalf("Error occurred while Writing reports: %v", err)
	}
}
