package models

import (
	"strings"

	trivyfanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
)

// Secrets related model
type DetectedSecret struct {
	Target    string `json:"Target"`
	RuleID    string `json:"-"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Code      Code   `json:"Code"`
	Match     string `json:"Match"`
}

type Code struct {
	Lines []Line `json:"Lines"`
}

type Line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

func ExtractTrivySecrets(res trivytypes.Result, index int) []DetectedSecret {
	// Omit match=created by, this is possible duplicate entries
	secrets := lo.Filter(res.Secrets, func(item trivytypes.DetectedSecret, index int) bool {
		return !strings.Contains(item.Match, "created_by")
	})

	return lo.Map(secrets, func(trSec trivytypes.DetectedSecret, index int) DetectedSecret {
		return DetectedSecret{
			Target:    res.Target,
			RuleID:    trSec.RuleID,
			Category:  string(trSec.Category),
			Severity:  trSec.Severity,
			Title:     trSec.Title,
			StartLine: trSec.StartLine,
			EndLine:   trSec.EndLine,
			Code: Code{
				Lines: lo.Map(trSec.Code.Lines, func(trLine trivyfanaltypes.Line, index int) Line {
					return Line{
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
