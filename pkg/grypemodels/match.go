package grypemodels

// Match is a single item for the JSON array reported
type Match struct {
	Vulnerability          Vulnerability           `json:"vulnerability"`
	RelatedVulnerabilities []VulnerabilityMetadata `json:"relatedVulnerabilities"`
	MatchDetails           []MatchDetails          `json:"matchDetails"`
	Artifact               Package                 `json:"artifact"`
}

// MatchDetails contains all data that indicates how the result match was found
type MatchDetails struct {
	Type       string      `json:"type"`
	Matcher    string      `json:"matcher"`
	SearchedBy interface{} `json:"searchedBy"` // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	Found      interface{} `json:"found"`      // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
	Fix        *FixDetails `json:"fix,omitempty"`
}

// FixDetails contains any data that is relevant to fixing the vulnerability specific to the package searched with
type FixDetails struct {
	SuggestedVersion string `json:"suggestedVersion"`
}
