package models

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"peek8.io/conscan/pkg/grypemodels"
)

type  CMDVulneResult struct {
	TrivyResult *types.Report
	GrypeResult *grypemodels.Document
}