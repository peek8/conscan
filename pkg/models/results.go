package models

import (
	"regexp"
	"strconv"
	"strings"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	docklereport "github.com/goodwithtech/dockle/pkg/report"
	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"peek8.io/conscan/pkg/grypemodels"
)

type ScanResult struct {
	TrivyResult     *trivytypes.Report
	GrypeResult     *grypemodels.Document
	SyftySBOMs      *spdxv23.Document
	CISScans        *docklereport.JsonOutputFormat
	StorageAnalysis *StorageAnalysis
}

// StorageAnalysis represents the parsed dive output
type StorageAnalysis struct {
	ImageSource       string            `json:"image_source"`
	Efficiency        float64           `json:"efficiency"`
	WastedBytes       int64             `json:"wasted_bytes"`
	WastedBytesHuman  string            `json:"wasted_bytes_human"`
	UserWastedPercent float64           `json:"user_wasted_percent"`
	InefficientFiles  []InefficientFile `json:"inefficient_files"`
	Results           []TestResult      `json:"results"`
}

// InefficientFile represents a file that's wasting space
type InefficientFile struct {
	Count       int    `json:"count"`
	WastedSpace string `json:"wasted_space"`
	FilePath    string `json:"file_path"`
}

func (ief *InefficientFile) IsZeroSpace() bool {
	fileRe := regexp.MustCompile(`([\d.]+)\s+[\w]+?`)

	if matches := fileRe.FindStringSubmatch(strings.TrimSpace(ief.WastedSpace)); matches != nil {
		if bytes, err := strconv.ParseFloat(matches[1], 64); err == nil {
			return bytes < 1
		}
	}

	return false
}

// TestResult represents a test result from dive
type TestResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}
