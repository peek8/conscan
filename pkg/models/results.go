package models

import (
	"fmt"
	"sort"
	"strings"

	trivydbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
	"peek8.io/conscan/pkg/grypemodels"
	"peek8.io/conscan/pkg/utils"
)

type CMDVulnerabilityResult struct {
	TrivyResult *trivytypes.Report
	GrypeResult *grypemodels.Document
}

func (cvr *CMDVulnerabilityResult) ToReport() (VulnerabilityReport, error) {
	fmt.Println("Trivy Vulnerabilities:: ", len(cvr.TrivyResult.Results[0].Vulnerabilities))
	fmt.Println("grype Vulnerabilities:: ", len(cvr.GrypeResult.Matches))

	vulns := cvr.aggregateVulnerabilities()
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].CvssScore > vulns[j].CvssScore
	})

	vr := VulnerabilityReport{
		CreatedAt:    cvr.TrivyResult.CreatedAt,
		ArtifactName: cvr.TrivyResult.ArtifactName,
		ArtifactType: string(cvr.TrivyResult.ArtifactType),
		Metadata: ImageMetadata{
			Size: cvr.TrivyResult.Metadata.Size,
			OS: OS{
				Name:   cvr.TrivyResult.Metadata.OS.Name,
				Family: string(cvr.TrivyResult.Metadata.OS.Family),
			},
			ImageID:     cvr.TrivyResult.Metadata.ImageID,
			RepoTags:    cvr.TrivyResult.Metadata.RepoTags,
			RepoDigests: cvr.TrivyResult.Metadata.RepoDigests,
			ImageConfig: ConfigFile{
				Architecture: cvr.TrivyResult.Metadata.ImageConfig.Architecture,
				Author:       cvr.TrivyResult.Metadata.ImageConfig.Author,
				Container:    cvr.TrivyResult.Metadata.ImageConfig.Container,
				Created:      cvr.TrivyResult.Metadata.ImageConfig.Created.Time,
			},
		},
		Vulnerabilities: vulns,
	}

	return vr, nil
}

func (cvr *CMDVulnerabilityResult) aggregateVulnerabilities() []DetectedVulnerability {
	trivyVulns := cvr.normalizeTrivyVulnerabilities(cvr.TrivyResult)
	grypeVulns := cvr.normalizeGripyVulnerabilities(cvr.GrypeResult)

	// Create Vunerability cache where the key is packageID + vulnerabilityID(CVE ID) ie libssl3@3.3.2-r4-CVE-2025-4575,
	trivyVulnMap := lo.SliceToMap(trivyVulns, func(v DetectedVulnerability) (string, DetectedVulnerability) {
		return fmt.Sprintf("%s-%s", v.PkgID, v.VulnerabilityID), v
	})

	grypVulnMap := lo.SliceToMap(grypeVulns, func(v DetectedVulnerability) (string, DetectedVulnerability) {
		return fmt.Sprintf("%s-%s", v.PkgID, v.VulnerabilityID), v
	})

	// Create Vunerability cache where  key is  vulnerabilityID(CVE ID) ie CVE-2025-4575,
	trivyCVEMap := lo.SliceToMap(trivyVulns, func(v DetectedVulnerability) (string, DetectedVulnerability) {
		return v.VulnerabilityID, v
	})

	grypCVEMap := lo.SliceToMap(grypeVulns, func(v DetectedVulnerability) (string, DetectedVulnerability) {
		return v.VulnerabilityID, v
	})

	vulnsKeys := lo.UniqKeys(trivyVulnMap, grypVulnMap)
	return lo.Map(vulnsKeys, func(key string, index int) DetectedVulnerability {
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

func (cvr *CMDVulnerabilityResult) normalizeTrivyVulnerabilities(tr *trivytypes.Report) []DetectedVulnerability {
	return lo.Map(tr.Results[0].Vulnerabilities, func(tv trivytypes.DetectedVulnerability, index int) DetectedVulnerability {
		vector, score := cvr.getTrivyCvss(tv)
		return DetectedVulnerability{
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

func (cvr *CMDVulnerabilityResult) getTrivyCvss(tv trivytypes.DetectedVulnerability) (string, float64) {
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

func (cvr *CMDVulnerabilityResult) normalizeGripyVulnerabilities(grypeDoc *grypemodels.Document) []DetectedVulnerability {
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
	return lo.Map(grypeDoc.Matches, func(m grypemodels.Match, index int) DetectedVulnerability {
		return DetectedVulnerability{
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
