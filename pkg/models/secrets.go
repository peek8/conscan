package models

// DetectedSecret Secrets related model
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

func (sec *DetectedSecret) DetectLocationType(artifactName string) LocationType {
	if sec.Target == artifactName {
		return LocationTypeEnvVar
	}

	return LocationTypeFileSystem
}

func (sec *DetectedSecret) DetermineDesc(artifactName string) string {
	if sec.Target == artifactName {
		return EnvVarSecretDescription
	}

	return FileSystemSecretDescription
}
