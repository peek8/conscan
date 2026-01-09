package models

import (
	"regexp"
	"strconv"
	"strings"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	docklereport "github.com/goodwithtech/dockle/pkg/report"
	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/peek8/conscan/pkg/grypemodels"
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
	ImageSource       string            `json:",omitempty"`
	Efficiency        float64           `json:","`
	WastedBytes       int64             `json:","`
	WastedBytesHuman  string            `json:","`
	UserWastedPercent float64           `json:","`
	InefficientFiles  []InefficientFile `json:","`
	Results           []TestResult      `json:","`
}

// InefficientFile represents a file that's wasting space
type InefficientFile struct {
	Count       int    `json:"Count"`
	WastedSpace string `json:"WastedSpace"`
	FilePath    string `json:"FilePath"`
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
