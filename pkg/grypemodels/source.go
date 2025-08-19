package grypemodels

type source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}
