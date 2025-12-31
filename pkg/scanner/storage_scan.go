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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/legacy/tarball"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/peek8/conscan/pkg/models"
	"github.com/peek8/conscan/pkg/utils"
)

func ScanForStorage(imageTag string) *models.StorageAnalysis {
	sa, err := diveScanForStorage(imageTag)
	if err != nil {
		utils.ExitOnError(err)
	}

	return sa
}

func diveScanForStorage(imageTag string) (*models.StorageAnalysis, error) {
	// If there is no image pull client fetch the image and store it as tarball
	if !utils.IsAnyImagePullClient() {
		return diveScanWithTarball(imageTag)
	}
	// run the scan for cis
	output, err, _ := utils.ExecuteCommandIgnoreExitCode("dive", "--ci", imageTag)

	// if there is an error, fallback to tarball
	if err != nil {
		return diveScanWithTarball(imageTag)
	}

	return parseDiveOutput(output)
}

func diveScanWithTarball(imageTag string) (*models.StorageAnalysis, error) {
	tmpGen := utils.NewTempDirGenerator("dive")
	// clean up temp dir
	defer tmpGen.Cleanup()

	tmpDir, _ := tmpGen.GetOrCreateRootLocation()
	tarFile, err := saveDockerTar(imageTag, tmpDir)
	if err != nil {
		return nil, fmt.Errorf("dive Error while saving docker archive: %v", err)
	}

	// run the scan for cis
	output, err, errStr := utils.ExecuteCommandIgnoreExitCode("dive", "--ci", "--source", "docker-archive", tarFile)
	if err != nil {
		return nil, fmt.Errorf("command execution failed: %v\nStderr: %s", err, errStr)
	}

	return parseDiveOutput(output)

}

// SaveDockerTar pulls an image and writes it as Docker-compatible tar for Dive
func saveDockerTar(imageRef, tmpDir string) (string, error) {
	// Parse image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("parsing image reference: %w", err)
	}

	outputTar := filepath.Join(tmpDir, ref.Identifier()+".tar")

	// Pull image from registry
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("pulling image failed: %w", err)
	}

	// Create output tar
	f, err := os.Create(outputTar)
	if err != nil {
		return "", fmt.Errorf("cannot create tar file: %w", err)
	}
	defer f.Close()

	// Write Docker-compatible tar
	if err := tarball.Write(ref, img, f); err != nil {
		return "", fmt.Errorf("writing docker tar failed: %w", err)
	}

	//fmt.Println("Image saved as Docker-compatible tar:", outputTar)
	return outputTar, nil
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
		return nil, fmt.Errorf("esrror while scanning parsing Dive output: %w", err)
	}

	return analysis, nil
}
