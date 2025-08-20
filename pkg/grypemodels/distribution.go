package grypemodels

// distribution provides information about a detected Linux distribution.
type distribution struct {
	Name     string   `json:"name"`               // Name of the Linux distribution
	Version  string   `json:"version"`            // Version of the Linux distribution (major or major.minor version)
	IDLike   []string `json:"idLike"`             // the ID_LIKE field found within the /etc/os-release file
	Channels []string `json:"channels,omitempty"` // channels for the distribution, if available
}
