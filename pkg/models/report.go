package models

import (
	"time"
)

type VulnerabilityReport struct {
	CreatedAt    time.Time `json:",omitzero"`
	ArtifactName string    `json:",omitempty"`
	ArtifactType string    `json:",omitempty"`

	Metadata        ImageMetadata `json:",omitzero"`
	Vulnerabilities []DetectedVulnerability
}

// DetectedVulnerability holds the information of detected vulnerabilities
type DetectedVulnerability struct {
	VulnerabilityID  string `json:",omitempty"`
	PkgID            string `json:",omitempty"` // It is used to construct dependency graph.
	PkgName          string `json:",omitempty"`
	InstalledVersion string `json:",omitempty"`
	FixedVersion     string `json:",omitempty"`
	Status           string `json:",omitempty"`

	// Embed vulnerability details
	Vulnerability
}

type Vulnerability struct {
	Title       string   `json:",omitempty"`
	Description string   `json:",omitempty"`
	Severity    string   `json:",omitempty"` // Selected from VendorSeverity, depending on a scan target
	CweIDs      []string `json:",omitempty"` // e.g. CWE-78, CWE-89
	//VendorSeverity   VendorSeverity `json:",omitempty"`
	CvssScore        float64    `json:",omitempty"`
	CvssVector       string     `json:",omitempty"`
	References       []string   `json:",omitempty"`
	PublishedDate    *time.Time `json:",omitempty"` // Take from NVD
	LastModifiedDate *time.Time `json:",omitempty"` // Take from NVD

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom any `json:",omitempty"`
}

type ImageMetadata struct {
	Size int64 `json:",omitempty"`
	OS   OS    `json:",omitempty"`

	// Container image
	ImageID     string     `json:",omitempty"`
	RepoTags    []string   `json:",omitempty"`
	RepoDigests []string   `json:",omitempty"`
	ImageConfig ConfigFile `json:",omitzero"`
}

type OS struct {
	Family string
	Name   string
}

// ConfigFile is the configuration file that holds the metadata describing
// how to launch a container. See:
// https://github.com/opencontainers/image-spec/blob/master/config.md
//
// docker_version and os.version are not part of the spec but included
// for backwards compatibility.
type ConfigFile struct {
	Architecture string    `json:"architecture"`
	Author       string    `json:"author,omitempty"`
	Container    string    `json:"container,omitempty"`
	Created      time.Time `json:"created,omitempty"`
}
