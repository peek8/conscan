package grypemodels

type IgnoredMatch struct {
	Match
	AppliedIgnoreRules []IgnoreRule `json:"appliedIgnoreRules"`
}

type IgnoreRule struct {
	Vulnerability    string             `json:"vulnerability,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	Namespace        string             `json:"namespace"`
	FixState         string             `json:"fix-state,omitempty"`
	Package          *IgnoreRulePackage `json:"package,omitempty"`
	VexStatus        string             `json:"vex-status,omitempty"`
	VexJustification string             `json:"vex-justification,omitempty"`
	MatchType        string             `json:"match-type,omitempty"`
}

type IgnoreRulePackage struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Language     string `json:"language"`
	Type         string `json:"type,omitempty"`
	Location     string `json:"location,omitempty"`
	UpstreamName string `json:"upstream-name,omitempty"`
}
