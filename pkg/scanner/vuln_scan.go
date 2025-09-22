package scanner

import (
	"encoding/json"
	"log"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"peek8.io/conscan/pkg/grypemodels"
	"peek8.io/conscan/pkg/utils"
)

func ScanVuln(imageTag string) (*trivytypes.Report, *grypemodels.Document) {
	// scan with trivy
	tr := scanTrivyVuln(imageTag)

	// Scan with grype
	gr := scanGrypeVuln(imageTag)

	return &tr, &gr
}

func scanTrivyVuln(imageTag string) trivytypes.Report {
	// run the trivy scan
	output, err, errStr := utils.ExecuteCommand("trivy", trivyVulnArgs(imageTag)...)

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	var report trivytypes.Report
	err = json.Unmarshal([]byte(output), &report)
	utils.ExitOnError(err)

	return report
}

func scanGrypeVuln(imageTag string) grypemodels.Document {
	// run the gruype scan
	output, err, errStr := utils.ExecuteCommand("grype", grypeVulnScanCmdArgs(imageTag)...)

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	var document grypemodels.Document
	err = json.Unmarshal([]byte(output), &document)
	utils.ExitOnError(err)

	return document
}

func grypeVulnScanCmdArgs(imageTag string) []string {
	return []string{imageTag, "-o", FormatJson}
}

func trivyGeneralArgs(imageTag string) []string {
	return []string{"image", imageTag, "-f", FormatJson}
}

func trivyVulnArgs(imageTag string) []string {
	return append(trivyGeneralArgs(imageTag), "--scanners", "vuln")
}

