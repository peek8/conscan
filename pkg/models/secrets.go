package models

import (
	"strings"

	trivyfanaltypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
	"peek8.io/conscan/pkg/utils"
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

type LocationType string

const (
	LocationTypeFileSystem LocationType = "FileSystem"
	LocationTypeEnvVar     LocationType = "EnvVar"

	// description for secret leak
	FileSystemSecretDescription = "Secret(s) found in file system"
	EnvVarSecretDescription     = "Secret(s) found in Environment Variables"
)

// Secrets related model
type DetectedPresSecret struct {
	Target    string `json:"Target"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Content   string `json:"Content"`
	//
	Description string `json:"Description"`
	// Location type could be filesystem, environment Variable
	LocationType LocationType `json:"LocationType"`
}

func detectSecretLocationType(secret DetectedSecret, artifactName string) LocationType {
	if secret.Target == artifactName {
		return LocationTypeEnvVar
	}

	return LocationTypeFileSystem
}

func ToPresSecrets(secrets []DetectedSecret, artifactName string) []DetectedPresSecret {
	return lo.Map(secrets, func(s DetectedSecret, index int) DetectedPresSecret {
		content := lo.Reduce(s.Code.Lines, func(agg string, line Line, index int) string {
			return utils.EitherOr(len(line.Content) > 0, agg+"\n"+line.Content, agg+line.Content)
		}, "")
		locationType := detectSecretLocationType(s, artifactName)

		return DetectedPresSecret{
			Target:       s.Target,
			Category:     s.Category,
			Severity:     s.Severity,
			Title:        s.Title,
			StartLine:    s.StartLine,
			EndLine:      s.EndLine,
			Content:      content,
			Description:  utils.EitherOr(locationType == LocationTypeFileSystem, FileSystemSecretDescription, EnvVarSecretDescription),
			LocationType: locationType,
		}
	})
}

func ExtractTrivyPresSecrets(res trivytypes.Result, artifactName string) []DetectedPresSecret {
	return ToPresSecrets(ExtractTrivySecrets(res), artifactName)
}

func ExtractTrivySecrets(res trivytypes.Result) []DetectedSecret {
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
