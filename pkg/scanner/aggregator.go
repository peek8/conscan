/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, September 2nd 2025, 6:46:14 pm
 * Author: Md. Asraful Haque
 *
 * -----
 * Last Modified: Tuesday, 2nd September 2025 6:46:14 pm
 * Modified By: Md. Asraful Haque
 * -----
 */

package scanner

import (
	"fmt"
	"sort"
	"strings"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivyfanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"

	"peek8.io/conscan/pkg/grypemodels"
	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/utils"
)

type VulnerabilitiesAggregrator struct {
	Result *models.VulnerabilityResult
}

func (vg *VulnerabilitiesAggregrator) AggregateVulnerabilities() []models.DetectedVulnerability {
	trivyVulns := vg.normalizeTrivyVulnerabilities()
	grypeVulns := vg.normalizeGripyVulnerabilities()

	vulns := vg.mergeVulnerabilities(trivyVulns, grypeVulns)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].CvssScore > vulns[j].CvssScore
	})

	return vulns
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
		return models.DetectedVulnerability{
			VulnerabilityID:  m.Vulnerability.ID,
			PkgID:            m.Artifact.Name + "@" + m.Artifact.Version,
			PkgName:          m.Artifact.Name,
			InstalledVersion: m.Artifact.Version,
			FixedVersion:     utils.EitherOrFunc(len(m.Vulnerability.Fix.Versions) > 0, func() string { return m.Vulnerability.Fix.Versions[0] }, ""),
			Status:           m.Vulnerability.Fix.State,
			Title:            getTitle(m),
			Description:      utils.EitherOrFunc(len(m.RelatedVulnerabilities) > 0, func() string { return m.RelatedVulnerabilities[0].Description }, m.Vulnerability.Description),
			Severity:         m.Vulnerability.Severity,
			//CweIDs: tv.CweIDs,
			CvssVector: m.Vulnerability.Cvss[0].Vector,
			CvssScore:  m.Vulnerability.Cvss[0].Metrics.BaseScore,
			References: []string{m.Vulnerability.DataSource},
			//PublishedDate: m.PublishedDate,
			//LastModifiedDate: m.LastModifiedDate,
		}
	})
}

type SecretsAggregrator struct {
	TrivyResult *trivytypes.Report
}

func (sg *SecretsAggregrator) ExtractSecrets() []models.DetectedPresSecret {
	// for now secrets are from only trivy
	return sg.ExtractTrivySecrets()
}

func (sg *SecretsAggregrator) ExtractTrivySecrets() []models.DetectedPresSecret {
	results := lo.Filter(sg.TrivyResult.Results, func(res trivytypes.Result, i int) bool {
		return res.Class == trivytypes.ClassSecret && len(res.Secrets) > 0
	})

	return lo.FlatMap(results, func(res trivytypes.Result, _ int) []models.DetectedPresSecret {
		return sg.ToPresSecrets(sg.ExtractTrivySecretsFromResult(res), sg.TrivyResult.ArtifactName)
	})
}

func (sg *SecretsAggregrator) ToPresSecrets(secrets []models.DetectedSecret, artifactName string) []models.DetectedPresSecret {
	return lo.Map(secrets, func(s models.DetectedSecret, index int) models.DetectedPresSecret {
		content := lo.Reduce(s.Code.Lines, func(agg string, line models.Line, index int) string {
			return utils.EitherOr(len(line.Content) > 0, agg+"\n"+line.Content, agg+line.Content)
		}, "")
		locationType := s.DetectLocationType(artifactName)

		return models.DetectedPresSecret{
			Target:       s.Target,
			Category:     s.Category,
			Severity:     s.Severity,
			Title:        s.Title,
			StartLine:    s.StartLine,
			EndLine:      s.EndLine,
			Content:      content,
			Description:  s.DetermineDesc(artifactName),
			LocationType: locationType,
		}
	})
}

func (sg *SecretsAggregrator) ExtractTrivySecretsFromResult(res trivytypes.Result) []models.DetectedSecret {
	// Omit match=created by, this is possible duplicate entries
	secrets := lo.Filter(res.Secrets, func(item trivytypes.DetectedSecret, index int) bool {
		return !strings.Contains(item.Match, "created_by")
	})

	return lo.Map(secrets, func(trSec trivytypes.DetectedSecret, index int) models.DetectedSecret {
		return models.DetectedSecret{
			Target:    res.Target,
			RuleID:    trSec.RuleID,
			Category:  string(trSec.Category),
			Severity:  trSec.Severity,
			Title:     trSec.Title,
			StartLine: trSec.StartLine,
			EndLine:   trSec.EndLine,
			Code: models.Code{
				Lines: lo.Map(trSec.Code.Lines, func(trLine trivyfanaltypes.Line, index int) models.Line {
					return models.Line{
						Number:      trLine.Number,
						Content:     trLine.Content,
						IsCause:     trLine.IsCause,
						Annotation:  trLine.Annotation,
						Truncated:   trLine.Truncated,
						Highlighted: trLine.Highlighted,
						FirstCause:  trLine.FirstCause,
						LastCause:   trLine.LastCause,
					}
				}),
			},
		}
	})
}

type SbomsAggregator struct {
	SyftySBOMs *spdxv23.Document
}

func (sa *SbomsAggregator) AggregateSboms() *spdxv23.Document {
	if sa.SyftySBOMs == nil {
		return nil
	}

	// copy the struct
	res := *sa.SyftySBOMs

	// omit relationships and files
	res.Relationships = []*spdxv23.Relationship{}
	res.Files = []*spdxv23.File{}

	return &res
}

type ReportAggregrator struct {
	Results *models.VulnerabilityResult

	va  *VulnerabilitiesAggregrator
	sa  *SecretsAggregrator
	sba *SbomsAggregator
}

func (ra *ReportAggregrator) newReport() *models.ScanReport {
	tr := ra.Results.TrivyResult

	return &models.ScanReport{
		CreatedAt:    tr.CreatedAt,
		ArtifactName: tr.ArtifactName,
		ArtifactType: string(tr.ArtifactType),
		Metadata: models.ImageMetadata{
			Size: tr.Metadata.Size,
			OS: models.OS{
				Name:   tr.Metadata.OS.Name,
				Family: string(tr.Metadata.OS.Family),
			},
			ImageID:     tr.Metadata.ImageID,
			RepoTags:    tr.Metadata.RepoTags,
			RepoDigests: tr.Metadata.RepoDigests,
			ImageConfig: models.ConfigFile{
				Architecture: tr.Metadata.ImageConfig.Architecture,
				Author:       tr.Metadata.ImageConfig.Author,
				Container:    tr.Metadata.ImageConfig.Container,
				Created:      tr.Metadata.ImageConfig.Created.Time,
			},
		},
	}
}

func (ra *ReportAggregrator) AggreagateReport() *models.ScanReport {
	sr := ra.newReport()
	sr.Vulnerabilities = ra.va.AggregateVulnerabilities()
	sr.Secrets = ra.sa.ExtractSecrets()
	sr.SBOMs = ra.sba.AggregateSboms()

	sr.VulnerabilitySummary = ra.generateVulnerabilitySummary(sr.Vulnerabilities)

	return sr
}

func (ra *ReportAggregrator) generateVulnerabilitySummary(vulns []models.DetectedVulnerability) *models.VulnerabilitySummary {
	getCountFunc := func(severity string) func(v models.DetectedVulnerability) bool {
		return func(v models.DetectedVulnerability) bool {
			return strings.ToUpper(v.Severity) == severity
		}
	}

	return &models.VulnerabilitySummary{
		CriticalCount: lo.CountBy(vulns, getCountFunc(models.SeverityNameCritical)),
		HighCount:     lo.CountBy(vulns, getCountFunc(models.SeverityNameHigh)),
		MediumCount:   lo.CountBy(vulns, getCountFunc(models.SeverityNameMedium)),
		LowCount:      lo.CountBy(vulns, getCountFunc(models.SeverityNameLow)),
		UnknowsCount:  lo.CountBy(vulns, getCountFunc(models.SeverityNameUnknown)),
	}
}

func NewReportAggregator(result *models.VulnerabilityResult) *ReportAggregrator {
	return &ReportAggregrator{
		Results: result,
		va:      &VulnerabilitiesAggregrator{Result: result},
		sa:      &SecretsAggregrator{TrivyResult: result.TrivyResult},
		sba:     &SbomsAggregator{SyftySBOMs: result.SyftySBOMs},
	}
}
