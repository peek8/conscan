/*
 * Copyright (c) 2026 peek8.io
 *
 * Created Date: Tuesday, January 6th 2026, 5:28:40 pm
 * Author: Md. Asraful Haque
 *
 */

package aggregator

import (
	"fmt"
	"sort"
	"strings"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"

	"github.com/peek8/conscan/pkg/grypemodels"
	"github.com/peek8/conscan/pkg/models"
	"github.com/peek8/conscan/pkg/utils"
)

type VulnerabilitiesAggregrator struct {
	Result *models.ScanResult
}

func (vg *VulnerabilitiesAggregrator) AggregateVulnerabilities() []models.DetectedVulnerability {
	trivyVulns := vg.normalizeTrivyVulnerabilities()
	grypeVulns := vg.normalizeGripyVulnerabilities()

	vulns := vg.mergeVulnerabilities(trivyVulns, grypeVulns)
	vulns = vg.omitTooManyVulnerabilities(vulns)

	vulns = vg.sortBySeverity(vulns)

	return vulns
}

func (vg *VulnerabilitiesAggregrator) aggregateProperties(vulns []models.DetectedVulnerability) []models.DetectedVulnerability {
	return lo.Map(vulns, func(v models.DetectedVulnerability, _ int) models.DetectedVulnerability {
		v.Title = utils.IfEmptyStr(v.Title, lo.Ellipsis(v.Description, 100))
		v.CvssScoreStr = utils.EitherOr(v.CvssScore > 0, fmt.Sprintf("%.2f", v.CvssScore), "Unknown")

		return v
	})

}

func (vg *VulnerabilitiesAggregrator) GenerateVulnerabilitySummary(vulns []models.DetectedVulnerability) *models.VulnerabilitySummary {
	getCountFunc := func(severity string) func(v models.DetectedVulnerability) bool {
		return func(v models.DetectedVulnerability) bool {
			return strings.ToUpper(v.Severity) == severity
		}
	}

	return &models.VulnerabilitySummary{
		TotalCount:    len(vulns),
		CriticalCount: lo.CountBy(vulns, getCountFunc(models.SeverityNameCritical)),
		HighCount:     lo.CountBy(vulns, getCountFunc(models.SeverityNameHigh)),
		MediumCount:   lo.CountBy(vulns, getCountFunc(models.SeverityNameMedium)),
		LowCount:      lo.CountBy(vulns, getCountFunc(models.SeverityNameLow)),
		UnknownCount:  lo.CountBy(vulns, getCountFunc(models.SeverityNameUnknown)),
	}
}

func (vg *VulnerabilitiesAggregrator) sortBySeverity(vulns []models.DetectedVulnerability) []models.DetectedVulnerability {
	vulns = lo.Map(vulns, func(v models.DetectedVulnerability, _ int) models.DetectedVulnerability {
		v.SeverityInt = models.ParseSeverity(v.Severity)

		return v
	})

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].SeverityInt > vulns[j].SeverityInt
	})

	return vulns
}

func (vg *VulnerabilitiesAggregrator) omitTooManyVulnerabilities(vulns []models.DetectedVulnerability) []models.DetectedVulnerability {
	// if there are too many vulnerabilities, omit based and priority
	if len(vulns) < 50 {
		return vulns
	}

	isSeverity := func(sev string) func(models.DetectedVulnerability) bool {
		return func(v models.DetectedVulnerability) bool {
			return strings.ToLower(v.Severity) == sev
		}
	}
	negligibleCount := lo.CountBy(vulns, isSeverity("negligible"))
	unknownCount := lo.CountBy(vulns, isSeverity("unknown"))

	res := vulns
	if len(res)-negligibleCount > 5 {
		res = lo.Filter(vulns, func(v models.DetectedVulnerability, index int) bool {
			return strings.ToLower(v.Severity) != "negligible"
		})
	}

	// If there are more than 50 vulnerabilities omitting the unknowns, omit those as well
	if len(res)-unknownCount > 50 {
		res = lo.Filter(res, func(v models.DetectedVulnerability, index int) bool {
			return strings.ToLower(v.Severity) != "unknown"
		})
	}

	return res
}

func (vg *VulnerabilitiesAggregrator) mergeVulnerabilities(trivyVulns, grypeVulns []models.DetectedVulnerability) []models.DetectedVulnerability {
	// Create Vunerability cache where the key is packageID + vulnerabilityID(CVE ID) ie libssl3@3.3.2-r4-CVE-2025-4575,
	trivyVulnMap := lo.SliceToMap(trivyVulns, func(v models.DetectedVulnerability) (string, models.DetectedVulnerability) {
		return fmt.Sprintf("%s-%s", v.PkgID, v.VulnerabilityID), v
	})

	grypVulnMap := lo.SliceToMap(grypeVulns, func(v models.DetectedVulnerability) (string, models.DetectedVulnerability) {
		return fmt.Sprintf("%s-%s", v.PkgID, v.VulnerabilityID), v
	})

	// Create Vunerability cache where  key is  vulnerabilityID(CVE ID) ie CVE-2025-4575,
	trivyCVEMap := lo.SliceToMap(trivyVulns, func(v models.DetectedVulnerability) (string, models.DetectedVulnerability) {
		return v.VulnerabilityID, v
	})

	grypCVEMap := lo.SliceToMap(grypeVulns, func(v models.DetectedVulnerability) (string, models.DetectedVulnerability) {
		return v.VulnerabilityID, v
	})

	vulnsKeys := lo.UniqKeys(trivyVulnMap, grypVulnMap)
	//fmt.Printf("Vulnerabilities Keys: %s \n", vulnsKeys)

	return lo.Map(vulnsKeys, func(key string, index int) models.DetectedVulnerability {
		trivyVuln, tOk := trivyVulnMap[key]
		grypeVuln, gOk := grypVulnMap[key]

		// if its common for two merge them
		if tOk && gOk {
			return trivyVuln.FromGrypeVuln(grypeVuln)
		} else if tOk {
			cve, ok := grypCVEMap[trivyVuln.VulnerabilityID]
			if ok {
				return trivyVuln.FromGrypeVuln(cve)
			}

			return trivyVuln
		}

		cve, ok := trivyCVEMap[grypeVuln.VulnerabilityID]
		if ok {
			return grypeVuln.FromTrivyVuln(cve)
		}
		return grypeVuln
	})
}

func (vg *VulnerabilitiesAggregrator) normalizeTrivyVulnerabilities() []models.DetectedVulnerability {
	if vg.Result.TrivyResult == nil {
		return []models.DetectedVulnerability{}
	}

	vRes, found := lo.Find(vg.Result.TrivyResult.Results, func(res trivytypes.Result) bool {
		return res.Class == trivytypes.ClassOSPkg && !res.IsEmpty()
	})

	if !found {
		return []models.DetectedVulnerability{}
	}

	return lo.Map(vRes.Vulnerabilities, func(tv trivytypes.DetectedVulnerability, index int) models.DetectedVulnerability {
		vector, score := vg.getTrivyCvss(tv)
		return models.DetectedVulnerability{
			VulnerabilityID:  tv.VulnerabilityID,
			PkgID:            tv.PkgID,
			PkgName:          tv.PkgName,
			DataSourceURL:    tv.PrimaryURL,
			InstalledVersion: tv.InstalledVersion,
			FixedVersion:     tv.FixedVersion,
			Status:           tv.Status.String(),
			Title:            tv.Title,
			Description:      tv.Description,
			Severity:         tv.Severity,
			CweIDs:           tv.CweIDs,
			CvssVector:       vector,
			CvssScore:        score,
			References:       tv.References,
			PublishedDate:    tv.PublishedDate,
			LastModifiedDate: tv.LastModifiedDate,
		}
	})
}

func (vg *VulnerabilitiesAggregrator) getTrivyCvss(tv trivytypes.DetectedVulnerability) (string, float64) {
	checkCvss := func(checker func(cvss trivydbtypes.CVSS) bool) (trivydbtypes.SourceID, bool) {
		return lo.FindKeyBy(tv.CVSS, func(key trivydbtypes.SourceID, cvss trivydbtypes.CVSS) bool {
			return checker(cvss)
		})
	}

	v40Key, found := checkCvss(func(cvss trivydbtypes.CVSS) bool { return cvss.V40Vector != "" })
	if found {
		return tv.CVSS[v40Key].V40Vector, tv.CVSS[v40Key].V40Score
	}

	v3Key, found := checkCvss(func(cvss trivydbtypes.CVSS) bool { return cvss.V3Vector != "" })
	if found {
		return tv.CVSS[v3Key].V3Vector, tv.CVSS[v3Key].V3Score
	}

	v2Key, found := checkCvss(func(cvss trivydbtypes.CVSS) bool { return cvss.V2Vector != "" })
	if found {
		return tv.CVSS[v2Key].V2Vector, tv.CVSS[v3Key].V2Score
	}

	return "", 0
}

func (vg *VulnerabilitiesAggregrator) normalizeGripyVulnerabilities() []models.DetectedVulnerability {
	if vg.Result.GrypeResult == nil {
		return []models.DetectedVulnerability{}
	}

	getTitle := func(m grypemodels.Match) string {
		if len(m.RelatedVulnerabilities) > 0 {
			// the description is in format like:
			// Issue summary: some summary Impact summary: detail summary
			// we will have title as imact summary
			index := strings.Index(m.RelatedVulnerabilities[0].Description, "Impact summary:")
			if index > -1 {
				title := m.RelatedVulnerabilities[0].Description[0:index]
				title, _ = strings.CutPrefix(title, "Issue summary:")

				return title
			}
		}

		return ""
	}

	return lo.Map(vg.Result.GrypeResult.Matches, func(m grypemodels.Match, index int) models.DetectedVulnerability {
		rv := lo.FirstOrEmpty(m.RelatedVulnerabilities)
		return models.DetectedVulnerability{
			VulnerabilityID:  m.Vulnerability.ID,
			PkgID:            m.Artifact.Name + "@" + m.Artifact.Version,
			PkgName:          m.Artifact.Name,
			DataSourceURL:    m.Vulnerability.DataSource,
			InstalledVersion: m.Artifact.Version,
			FixedVersion:     lo.FirstOr(m.Vulnerability.Fix.Versions, ""),
			Status:           m.Vulnerability.Fix.State,
			Title:            getTitle(m),
			Description:      utils.EitherOr(rv.Description != "", rv.Description, m.Vulnerability.Description),
			Severity:         m.Vulnerability.Severity,
			//CweIDs: tv.CweIDs,

			CvssVector: m.Vulnerability.GetCVSSVector(),
			CvssScore:  m.Vulnerability.GetCVSSScore(),
			References: []string{m.Vulnerability.DataSource},
			//PublishedDate: m.PublishedDate,
			//LastModifiedDate: m.LastModifiedDate,
		}
	})
}
