/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Saturday, September 6th 2025, 8:01:00 pm
 * Author: Md. Asraful Haque
 *
 */

// Package utils contains utils function
package utils

import (
	"fmt"
	"os/exec"
)

const (
	// Decimal
	KB = 1000
	MB = 1000 * KB
	GB = 1000 * MB
	TB = 1000 * GB
	PB = 1000 * TB
)

func HumanReadableSize(bytes int64) string {
	if bytes < MB {
		return fmt.Sprintf("%d KB", bytes/KB)
	} else if bytes < GB {
		return fmt.Sprintf("%d MB", bytes/MB)
	}

	return fmt.Sprintf("%d GB", bytes/GB)
}

func IsDockerClientBinaryAvailable() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func IsPodmanClientBinaryAvailable() bool {
	_, err := exec.LookPath("podman")
	return err == nil
}

func IsAnyImagePullClient() bool {
	return IsDockerClientBinaryAvailable() || IsPodmanClientBinaryAvailable()
}
