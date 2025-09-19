/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Wednesday, September 3rd 2025, 1:11:03 pm
 * Author: Md. Asraful Haque
 *
 */

package models

import (
	"fmt"
	"slices"
)

type OutputFormat string

const (
	FormatJson  OutputFormat = "json"
	FormatTable OutputFormat = "table"
	FormatHtml  OutputFormat = "html"
)

var SupportedFormats = []OutputFormat{
	FormatJson, FormatTable, FormatHtml,
}

type ScanOptions struct {
	Format     OutputFormat
	OutputFile string
	Quiet      bool
}

func (opt ScanOptions) Validate() (string, bool) {
	if len(opt.Format) == 0 {
		return fmt.Sprintf("Format must not be empty, supported formats are:: %s", SupportedFormats), false
	}

	if !slices.Contains(SupportedFormats, OutputFormat(opt.Format)) {
		return fmt.Sprintf("Unsupported Format value %s, supported formats are: %s", opt.Format, SupportedFormats), false
	}

	return "", true
}
