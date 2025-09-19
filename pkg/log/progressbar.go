/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Friday, September 19th 2025, 7:46:41 pm
 * Author: Md. Asraful Haque
 *
 */

// Package log contains log related functionalities
package log

import (
	"os"
	"time"

	"github.com/briandowns/spinner"
)

var (
	MagnifyGlasses = []string{"🔎", " 🔎", "🔍", "🔍 "}
)

func StartSprinner(task string, spinnerCharSets []string, out *os.File) *spinner.Spinner {
	s := spinner.New(spinnerCharSets, 300*time.Millisecond, spinner.WithWriterFile(out))

	s.Suffix = " " + task
	s.Start()

	return s
}
