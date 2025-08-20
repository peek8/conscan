package grypemodels

// Package is meant to be only the fields that are needed when displaying a single pkg.Package object for the JSON presenter.
type Package struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Type         any               `json:"type"`
	Locations    any               `json:"locations"`
	Language     any               `json:"language"`
	Licenses     []string          `json:"licenses"`
	CPEs         []string          `json:"cpes"`
	PURL         string            `json:"purl"`
	Upstreams    []UpstreamPackage `json:"upstreams"`
	MetadataType string            `json:"metadataType,omitempty"`
	Metadata     interface{}       `json:"metadata,omitempty"`
}

type UpstreamPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}
