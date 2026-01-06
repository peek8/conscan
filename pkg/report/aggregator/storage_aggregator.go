/*
 * Copyright (c) 2026 peek8.io
 *
 * Created Date: Tuesday, January 6th 2026, 6:13:13 pm
 * Author: Md. Asraful Haque
 *
 */

package aggregator

import (
	"github.com/peek8/conscan/pkg/models"
	"github.com/samber/lo"
)

type StorageAggregator struct {
	StorageAnalysis *models.StorageAnalysis
}

func (sta *StorageAggregator) AggregateStorage() *models.StorageAnalysis {
	if sta.StorageAnalysis == nil {
		return nil
	}

	sta.StorageAnalysis.InefficientFiles = lo.Filter(sta.StorageAnalysis.InefficientFiles, func(f models.InefficientFile, index int) bool {
		return !f.IsZeroSpace()
	})

	return sta.StorageAnalysis
}
