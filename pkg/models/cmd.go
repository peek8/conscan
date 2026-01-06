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
	"net/url"
	"slices"

	"github.com/samber/lo"
)

type OutputFormat string
type ScannerType string

const (
	// formats
	FormatJson  OutputFormat = "json"
	FormatTable OutputFormat = "table"
	FormatHtml  OutputFormat = "html"

	// scanners
	ScannerVulnerability ScannerType = "vuln"
	ScannerSecret        ScannerType = "secret"
	ScannerPackage       ScannerType = "package"
	ScannerCIS           ScannerType = "cis"
	ScannerStorage       ScannerType = "storage"
	ScannerAll           ScannerType = "all"
)

func (of OutputFormat) Equal(f OutputFormat) bool {
	return of == f
}

var SupportedFormats = []OutputFormat{
	FormatJson, FormatTable, FormatHtml,
}

var SupportedScanners = []ScannerType{
	ScannerVulnerability, ScannerSecret, ScannerPackage, ScannerCIS, ScannerStorage, ScannerAll,
}

type ScanOptions struct {
	Format     OutputFormat
	OutputFile string
	UploadURL  string
	Scanners   []ScannerType
	Quiet      bool
	Upload     bool
}

func (opt *ScanOptions) SetScanners(scanners []string) {
	opt.Scanners = lo.Map(scanners, func(s string, _ int) ScannerType {
		return ScannerType(s)
	})
}

func (opt *ScanOptions) HasScanner(st ScannerType) bool {
	if slices.Contains(opt.Scanners, ScannerAll) {
		return true
	}

	return slices.Contains(opt.Scanners, st)
}

func (opt *ScanOptions) Validate() (string, bool) {
	if msg, ok := opt.ValidateFormat(); !ok {
		return msg, false
	}

	if msg, ok := opt.ValidateScanners(); !ok {
		return msg, false
	}

	if opt.Upload {
		if msg, ok := opt.ValidateUploadURL(opt.UploadURL); !ok {
			return msg, false
		}
	}

	return "", true
}

func (opt *ScanOptions) ValidateScanners() (string, bool) {
	unsupportedScanner := lo.Filter(opt.Scanners, func(s ScannerType, _ int) bool {
		return !slices.Contains(SupportedScanners, s)
	})

	if len(unsupportedScanner) > 0 {
		return fmt.Sprintf("Unsupported Scanners %s, supported scanners are: %s", unsupportedScanner, SupportedScanners), false
	}

	return "", true
}

func (opt *ScanOptions) ValidateFormat() (string, bool) {
	if len(opt.Format) == 0 {
		return fmt.Sprintf("Format must not be empty, supported formats are:: %s", SupportedFormats), false
	}

	if !slices.Contains(SupportedFormats, opt.Format) {
		return fmt.Sprintf("Unsupported Format value %s, supported formats are: %s", opt.Format, SupportedFormats), false
	}

	return "", true
}

func (opt *ScanOptions) ValidateUploadURL(uploadUrl string) (string, bool) {
	u, err := url.ParseRequestURI(uploadUrl)
	if err != nil {
		return fmt.Sprintf("invalid URL: %v", err), false
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "URL must start with http:// or https://", false
	}

	if u.Host == "" {
		return "URL must have a host", false
	}

	return "", true
}
