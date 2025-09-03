package models

import (
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"peek8.io/conscan/pkg/grypemodels"
)

type VulnerabilityResult struct {
	TrivyResult *trivytypes.Report
	GrypeResult *grypemodels.Document
	SyftySBOMs  *spdxv23.Document
}
