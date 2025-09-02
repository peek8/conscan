package utils

import (
	"bytes"
	"os/exec"
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
