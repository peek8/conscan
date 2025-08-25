package scanner

import (
	"encoding/json"
	"fmt"
	"log"
)

func ScanImage(imageTag string) {
	result, err := ScanVuln(imageTag)
	if err != nil {
		log.Fatalf("Error occurred while scanning image for vulnerabilities %v", err)
	}

	report, err := result.ToReport()
	if err != nil {
		log.Fatalf("Error occurred while generating reports %v", err)
	}

	out, err := json.MarshalIndent(report, "", "	")
	if err != nil {
		log.Fatalf("Error occurred while Converting reports to json %v", err)
	}

	fmt.Println(string(out))
}
