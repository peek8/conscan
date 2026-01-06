/*
 * Copyright (c) 2026 peek8.io
 *
 * Created Date: Tuesday, January 6th 2026, 5:32:03 pm
 * Author: Md. Asraful Haque
 *
 */

package aggregator

import (
	"sort"

	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type SbomsAggregator struct {
	SyftySBOMs *spdxv23.Document
}

func (sa *SbomsAggregator) AggregateSboms() *spdxv23.Document {
	if sa.SyftySBOMs == nil {
		return nil
	}

	// copy the struct
	res := *sa.SyftySBOMs

	sort.Slice(res.Packages, func(i, j int) bool {
		// Sorts in ascending alphabetical order by Name
		return res.Packages[i].PackageName < res.Packages[j].PackageName
	})

	// omit relationships and files
	res.Relationships = []*spdxv23.Relationship{}
	res.Files = []*spdxv23.File{}

	return &res
}
