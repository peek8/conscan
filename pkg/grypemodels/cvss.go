package grypemodels

type Cvss struct {
	Source         string      `json:"source,omitempty"`
	Type           string      `json:"type,omitempty"`
	Version        string      `json:"version"`
	Vector         string      `json:"vector"`
	Metrics        CvssMetrics `json:"metrics"`
	VendorMetadata interface{} `json:"vendorMetadata"`
}

type CvssMetrics struct {
	BaseScore           float64  `json:"baseScore"`
	ExploitabilityScore *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64 `json:"impactScore,omitempty"`
}
