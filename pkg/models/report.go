package models

import (
	"time"
)

type ScanReport struct {
	CreatedAt    time.Time `json:",omitzero"`
	ArtifactName string    `json:",omitempty"`
	ArtifactType string    `json:",omitempty"`

	Metadata        ImageMetadata `json:",omitzero"`
	Vulnerabilities []DetectedVulnerability
	Secrets         []DetectedPresSecret
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
