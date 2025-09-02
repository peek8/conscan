package models

import (
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"peek8.io/conscan/pkg/grypemodels"
)

type VulnerabilityResult struct {
	TrivyResult *trivytypes.Report
	GrypeResult *grypemodels.Document
}
