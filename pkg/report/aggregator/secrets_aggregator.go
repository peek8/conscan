/*
 * Copyright (c) 2026 peek8.io
 *
 * Created Date: Tuesday, January 6th 2026, 5:30:40 pm
 * Author: Md. Asraful Haque
 *
 */

package aggregator

import (
	"fmt"
	"strings"

	trivyfanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/peek8/conscan/pkg/models"
	"github.com/peek8/conscan/pkg/utils"
	"github.com/samber/lo"
)

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

		lineNumbers := lo.Map(s.Code.Lines, func(line models.Line, index int) int {
			return line.Number
		})
		location := lo.Ternary(locationType == models.LocationTypeFileSystem, fmt.Sprintf("%s:%d:%d", s.Target, s.StartLine, s.EndLine), "Environment Variables")

		return  models.DetectedPresSecret{
			Target:       s.Target,
			Category:     s.Category,
			Severity:     s.Severity,
			Title:        s.Title,
			StartLine:    lo.Min(lineNumbers),
			EndLine:      lo.Max(lineNumbers),
			Content:      content,
			Description:  s.DetermineDesc(artifactName),
			LocationType: locationType,
			Location: location,
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
