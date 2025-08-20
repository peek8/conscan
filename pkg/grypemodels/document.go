package grypemodels

// Document represents the JSON document to be presented
type Document struct {
	Matches        []Match        `json:"matches"`
	IgnoredMatches []IgnoredMatch `json:"ignoredMatches,omitempty"`
	Source         *source        `json:"source"`
	Distro         distribution   `json:"distro"`
	Descriptor     descriptor     `json:"descriptor"`
}
