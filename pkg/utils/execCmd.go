package utils

import (
	"bytes"
	"os/exec"
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

func ExecuteCommand(cmdName string, args ...string) (string, error, string) {
	// Define the command and its arguments
	// cmd := exec.Command(  "trivy", "-d",  "image", "alpine:edge", "--scanners", "vuln", "-f", "json" )
	cmd := exec.Command(cmdName, args...)

	// Create buffers to capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	err := cmd.Run()
	if err != nil {
		//log.Fatalf("Command execution failed: %v\nStderr: %s", err, stderr.String())
		return "", err, stderr.String()
	}

	return stdout.String(), nil, ""
}

func TrivyVulnScanCmdArgs(imageTag string) []string {
	// return append(trivyGeneralArgs(imageTag), "--scanners", TrivyScannerVulnFlag)
	return trivyGeneralArgs(imageTag)
}

func GrypeVulnScanCmdArgs(imageTag string) []string {
	return []string{imageTag, "-o", FormatJson}
}

func trivyGeneralArgs(imageTag string) []string {
	return []string{"image", imageTag, "-f", FormatJson}
}
