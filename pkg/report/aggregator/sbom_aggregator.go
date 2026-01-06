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
	"strings"

	"github.com/samber/lo"
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
	res.Packages = sa.normalizePackages(res.Packages)

	sort.Slice(res.Packages, func(i, j int) bool {
		// Sorts in ascending alphabetical order by Name
		return res.Packages[i].PackageName < res.Packages[j].PackageName
	})

	// omit relationships and files
	res.Relationships = []*spdxv23.Relationship{}
	res.Files = []*spdxv23.File{}

	return &res
}

func (sa *SbomsAggregator) normalizePackages(packages []*spdxv23.Package) []*spdxv23.Package {
	// omit duplicates that has same package and version
	uniquePkgs := lo.UniqBy(packages, func(pkg *spdxv23.Package) string {
		return pkg.PackageName + pkg.PackageVersion
	})

	// same packages but  different version
	multiVersionPkgs := lo.GroupBy(uniquePkgs, func(pkg *spdxv23.Package) string {
		return pkg.PackageName + pkg.PackageDescription
	})

	multiVersionPkgsNormalized := lo.MapToSlice(multiVersionPkgs, func(_ string, pkgs []*spdxv23.Package) []*spdxv23.Package {
		if len(pkgs) == 1 {
			return pkgs
		}
		versions := lo.Reduce(pkgs, func(version string, item *spdxv23.Package, _ int) string {
			return version + ", " + item.PackageVersion
		}, "")

		pkgs[0].PackageVersion = strings.TrimPrefix(versions, ",")
		return []*spdxv23.Package{pkgs[0]}
	})

	return lo.Flatten(multiVersionPkgsNormalized)
}
