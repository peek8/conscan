package scanner

import (
	"encoding/json"
	"log"

	"github.com/peek8/conscan/pkg/utils"
	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func SyftScanForSboms(imageTag string) *spdxv23.Document {
	// run the trivy scan
	output, err, errStr := utils.ExecuteCommand("syft", imageTag, "-o", "spdx-json")

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	var docs spdxv23.Document
	err = json.Unmarshal([]byte(output), &docs)
	if err != nil {
		utils.ExitOnError(err)
	}

	return &docs
}
