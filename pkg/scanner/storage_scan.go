/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Thursday, September 11th 2025, 10:40:23 am
 * Author: Md. Asraful Haque
 *
 */

package scanner

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/utils"
)

func DiveScanForStorage(imageTag string) *models.StorageAnalysis {
	// run the scan for cis
	output, err, errStr := utils.ExecuteCommand("dive", "--ci", imageTag)

	if err != nil {
		log.Fatalf("Command execution failed: %v\nStderr: %s", err, errStr)
	}

	diveAnalysis, err := parseDiveOutput(output)
	if err != nil {
		utils.ExitOnError(err)
	}

	return diveAnalysis
}

// parseDiveOutput parses the dive command output and returns structured data
func parseDiveOutput(output string) (*models.StorageAnalysis, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	analysis := &models.StorageAnalysis{}

	// Regular expressions for parsing
	imageSourceRe := regexp.MustCompile(`^Image Source: (.+)$`)
	efficiencyRe := regexp.MustCompile(`^\s+efficiency:\s+([\d.]+)\s*%$`)
	wastedBytesRe := regexp.MustCompile(`^\s+wastedBytes:\s+(\d+)\s+bytes\s+\((.+)\)$`)
	userWastedRe := regexp.MustCompile(`^\s+userWastedPercent:\s+([\d.]+)\s*%$`)
	//fileRe := regexp.MustCompile(`^\s*(\d+)\s+(.+?)\s+(.+)$`)
	fileRe := regexp.MustCompile(`^\s*(\d+)\s+(.+?\s[\w]+?)\s+(.+)$`)
	resultRe := regexp.MustCompile(`^\s*(PASS|FAIL|SKIP):\s+([^:]+)(?::\s*(.+))?$`)

	var inInefficientFiles bool
	var inResults bool

	for scanner.Scan() {
		line := scanner.Text()

		// Parse image source
		if matches := imageSourceRe.FindStringSubmatch(line); matches != nil {
			analysis.ImageSource = matches[1]
			continue
		}

		// Parse efficiency
		if matches := efficiencyRe.FindStringSubmatch(line); matches != nil {
			if val, err := strconv.ParseFloat(matches[1], 64); err == nil {
				analysis.Efficiency = val
			}
			continue
		}

		// Parse wasted bytes
		if matches := wastedBytesRe.FindStringSubmatch(line); matches != nil {
			if val, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
				analysis.WastedBytes = val
				analysis.WastedBytesHuman = matches[2]
			}
			continue
		}

		// Parse user wasted percent
		if matches := userWastedRe.FindStringSubmatch(line); matches != nil {
			if val, err := strconv.ParseFloat(matches[1], 64); err == nil {
				analysis.UserWastedPercent = val
			}
			continue
		}

		// Check for section headers
		if strings.Contains(line, "Inefficient Files:") {
			inInefficientFiles = true
			inResults = false
			continue
		}

		if strings.Contains(line, "Results:") {
			inResults = true
			inInefficientFiles = false
			continue
		}

		// Parse inefficient files
		if inInefficientFiles && strings.TrimSpace(line) != "" {
			// Skip header line
			if strings.Contains(line, "Count") && strings.Contains(line, "Wasted Space") {
				continue
			}

			if matches := fileRe.FindStringSubmatch(line); matches != nil {
				if count, err := strconv.Atoi(matches[1]); err == nil {
					file := models.InefficientFile{
						Count:       count,
						WastedSpace: strings.TrimSpace(matches[2]),
						FilePath:    strings.TrimSpace(matches[3]),
					}
					analysis.InefficientFiles = append(analysis.InefficientFiles, file)
				}
			}
		}

		// Parse results
		if inResults && strings.TrimSpace(line) != "" {
			if matches := resultRe.FindStringSubmatch(line); matches != nil {
				result := models.TestResult{
					Status: matches[1],
					Name:   strings.TrimSpace(matches[2]),
				}
				if len(matches) > 3 && matches[3] != "" {
					result.Reason = strings.TrimSpace(matches[3])
				}
				analysis.Results = append(analysis.Results, result)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning input: %w", err)
	}

	return analysis, nil
}
