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
	"encoding/json"
	"fmt"
	"log"
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

func ScanImage(imageTag string) {
	result := ScanVuln(imageTag)

	ra := NewReportAggregator(result)
	report := ra.AggreagateReport()

	out, err := json.MarshalIndent(report, "", "	")
	if err != nil {
		log.Fatalf("Error occurred while Converting reports to json %v", err)
	}

	fmt.Println(string(out))
}
