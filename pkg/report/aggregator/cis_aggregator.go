/*
 * Copyright (c) 2026 peek8.io
 *
 * Created Date: Tuesday, January 6th 2026, 5:33:11 pm
 * Author: Md. Asraful Haque
 *
 */

package aggregator

import (
	docklereport "github.com/goodwithtech/dockle/pkg/report"
)

type CISAggregator struct {
	CISScans *docklereport.JsonOutputFormat
}

func (ca *CISAggregator) AggregateCIS() *docklereport.JsonOutputFormat {
	return ca.CISScans
}
