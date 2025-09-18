package utils

import (
	"bytes"
	"os/exec"
	"syscall"
)

func ExecuteCommand(cmdName string, args ...string) (string, error, string) {
	// Define the command and its arguments
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

func ExecuteCommandIgnoreExitCode(cmdName string, args ...string) (string, error, string) {
	cmd := exec.Command(cmdName, args...)

	// Create buffers to capture stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	err := cmd.Run()
	outStr := stdout.String()

	if err != nil && outStr == "" {
		return "", err, stderr.String()
	}

	// there is an error but with some stdout
	if err != nil {
		// Check if it's an ExitError (process finished but with non-zero code)
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Extract exit code
			if _, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				// fmt.Println("Exit Code:", status.ExitStatus())
				return outStr, nil, ""
			}
		} else {
			// Other kinds of errors (e.g., command not found)
			return "", err, stderr.String()
		}
	}

	return outStr, nil, ""
}
