/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Sunday, September 21st 2025, 7:50:21 pm
 * Author: Md. Asraful Haque
 *
 */

package scanner

import (
	"encoding/json"
	"log"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"peek8.io/conscan/pkg/utils"
)

func scanSecrets(imageTag string) trivytypes.Report {
	// run the trivy scan
	output, err, errStr := utils.ExecuteCommand("trivy", trivySecretArgs(imageTag)...)

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	var report trivytypes.Report
	err = json.Unmarshal([]byte(output), &report)
	utils.ExitOnError(err)

	return report
}

func trivySecretArgs(imageTag string) []string {
	return append(trivyGeneralArgs(imageTag), "--scanners", "secret")
}
