/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, September 2nd 2025, 6:46:14 pm
 * Author: Md. Asraful Haque
 *
 */

// Package aggregator aggregates different types of report
package aggregator

import (
	"fmt"

	"github.com/samber/lo"

	"github.com/peek8/conscan/pkg/models"
	"github.com/peek8/conscan/pkg/utils"
)

type ReportAggregrator struct {
	Results     *models.ScanResult
	ScanOptions models.ScanOptions

	va  *VulnerabilitiesAggregrator
	sa  *SecretsAggregrator
	sba *SbomsAggregator
	sta *StorageAggregator
	ca  *CISAggregator
}

func (ra *ReportAggregrator) newReport() *models.ScanReport {
	tr := ra.Results.TrivyResult

	unknownOS := models.OS{
		Name:   "-",
		Family: "-",
	}

	return &models.ScanReport{
		CreatedAt:    tr.CreatedAt,
		CreatedAtStr: fmt.Sprintf("%s UTC", tr.CreatedAt.UTC().Format("2006-01-02 15:04:05")),
		ArtifactName: tr.ArtifactName,
		ArtifactType: string(tr.ArtifactType),
		Metadata: models.ImageMetadata{
			Size:    tr.Metadata.Size,
			SizeStr: utils.HumanReadableSize(tr.Metadata.Size),
			OS: utils.EitherOrFunc(lo.IsNotNil(tr.Metadata.OS), func() models.OS {
				return models.OS{
					Name:   tr.Metadata.OS.Name,
					Family: string(tr.Metadata.OS.Family),
				}
			}, unknownOS),
			ImageID:     tr.Metadata.ImageID,
			RepoTags:    tr.Metadata.RepoTags,
			RepoDigests: tr.Metadata.RepoDigests,
			ImageConfig: models.ConfigFile{
				Architecture: tr.Metadata.ImageConfig.Architecture,
				OS:           tr.Metadata.ImageConfig.OS,
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
	sr.CISScans = ra.ca.AggregateCIS()
	sr.StorageAnalysis = ra.sta.AggregateStorage()

	if ra.ScanOptions.HasScanner(models.ScannerVulnerability) {
		// this needs to be done after AggregateVulnerabilities
		sr.VulnerabilitySummary = ra.va.GenerateVulnerabilitySummary(sr.Vulnerabilities)
	}

	return sr
}

func NewReportAggregator(result *models.ScanResult, opts models.ScanOptions) *ReportAggregrator {
	return &ReportAggregrator{
		Results:     result,
		ScanOptions: opts,
		va:          &VulnerabilitiesAggregrator{Result: result},
		sa:          &SecretsAggregrator{TrivyResult: result.TrivyResult},
		sba:         &SbomsAggregator{SyftySBOMs: result.SyftySBOMs},
		sta:         &StorageAggregator{StorageAnalysis: result.StorageAnalysis},
		ca:          &CISAggregator{CISScans: result.CISScans},
	}
}
