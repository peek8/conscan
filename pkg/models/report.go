/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Wednesday, August 20th 2025, 3:28:54 pm
 * Author: Md. Asraful Haque
 *
 * -----
 * Last Modified: Tuesday, 2nd September 2025 5:30:01 pm
 * Modified By: Md. Asraful Haque
 * -----
 */

// Package models provide the struct for the data
package models

import (
	"time"

	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type ScanReport struct {
	CreatedAt    time.Time `json:",omitzero"`
	ArtifactName string    `json:",omitempty"`
	ArtifactType string    `json:",omitempty"`

	Metadata             ImageMetadata           `json:"metadata,omitzero"`
	Vulnerabilities      []DetectedVulnerability `json:"vulnerabilities,omitempty"`
	VulnerabilitySummary *VulnerabilitySummary   `json:"vulnerabilitySummary,omitempty"`
	Secrets              []DetectedPresSecret    `json:"secrets,omitempty"`
	SBOMs                *spdxv23.Document       `json:"sboms,omitzero"`
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

type VulnerabilitySummary struct {
	CriticalCount int `json:"criticalCount"`
	HighCount     int `json:"highCount"`
	MediumCount   int `json:"mediumCount"`
	LowCount      int `json:"lowCount"`
	UnknowsCount  int `json:"unknowsCount"`
}
