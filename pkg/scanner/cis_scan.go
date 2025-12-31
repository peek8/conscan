/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, September 9th 2025, 3:57:17 pm
 * Author: Md. Asraful Haque
 *
 */

package scanner

import (
	"encoding/json"
	"log"

	docklereport "github.com/goodwithtech/dockle/pkg/report"
	"github.com/peek8/conscan/pkg/utils"
)

func DockleScanForCIS(imageTag string) *docklereport.JsonOutputFormat {
	// run the scan for cis
	output, err, errStr := utils.ExecuteCommand("dockle", "-f", "json", imageTag)

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	var dockleOut docklereport.JsonOutputFormat
	err = json.Unmarshal([]byte(output), &dockleOut)
	if err != nil {
		utils.ExitOnError(err)
	}

	return &dockleOut
}
