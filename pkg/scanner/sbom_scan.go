package scanner

import (
	"encoding/json"
	"fmt"
	"log"

	spdxv23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"peek8.io/conscan/pkg/utils"
)

func scanImageForSboms(imageTag string) {
	docs, err := syftScanForSboms(imageTag)

	if err != nil {
		log.Fatalf("Error while getting sboms %v", err)
	}

	out, err := json.MarshalIndent(docs, "", "	")
	if err != nil {
		log.Fatalf("Error occurred while Converting reports to json %v", err)
	}

	fmt.Println(string(out))
}

func syftScanForSboms(imageTag string) (spdxv23.Document, error) {
	// run the trivy scan
	output, err, errStr := utils.ExecuteCommand("syft", imageTag, "-o", "spdx-json")

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	var docs spdxv23.Document
	err = json.Unmarshal([]byte(output), &docs)
	if err != nil {
		log.Fatalf("Error unmashalling error %v", err)
	}

	return docs, nil
}
