package scanner

import "log"

func ScanImage(imageTag string) {
	_, err := ScanVuln(imageTag)

	if err != nil {
		log.Fatalf("Error while scanning vulnerability from image %v", err)
	}

	// merge and deduplicate vulnerability
}
