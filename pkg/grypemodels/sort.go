package grypemodels

type SortStrategy string

const (
	SortByPackage       SortStrategy = "package"
	SortBySeverity      SortStrategy = "severity"
	SortByThreat        SortStrategy = "epss"
	SortByRisk          SortStrategy = "risk"
	SortByKEV           SortStrategy = "kev"
	SortByVulnerability SortStrategy = "vulnerability"

	DefaultSortStrategy = SortByRisk
)
