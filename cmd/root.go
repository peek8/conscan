/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, August 19th 2025, 11:30:40 am
 * Author: Md. Asraful Haque
 *
 */

// Package cmd contains all the commands and subcommands to scan the image
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCMDUsage = `Scan a container image for vulnerabilities, exposed secrets, inefficient file storage, installed packages and check CIS(Center for Internet Security) Benchmarks.
Supports the following image sources:
    conscan scan yourimage:tag				defaults to using local images from a Docker/Podman daemon
    conscan scan registry/yourrepo/yourimage:tag  	pull image directly from a registry (no container runtime required)

Examples:	
# Scan a container image locally available
$ conscan scan yourimage:tag          // uses the Podman/Docker daemon for local images

# Scan container images from registry eg. dockerhub
$ conscan scan docker.io/yourimage:tag

# or from github image repo
$ conscan scan ghcr.io/yourimage:tag`

type Identification struct {
	Name      string `json:"application,omitempty"`
	Version   string `json:"version,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
	BuildDate string `json:"buildDate,omitempty"`
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(identiifcaton Identification) {
	rootCmd := create(identiifcaton)

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func create(identiifcaton Identification) *cobra.Command {
	rootCmd := Root(identiifcaton)

	rootCmd.AddCommand(
		VersionCommand(identiifcaton),
		scanCmd,
	)

	return rootCmd
}

func Root(identiifcaton Identification) *cobra.Command {
	var showVersion bool
	// rootCmd represents the base command when called without any subcommands
	rootCmd := &cobra.Command{
		Args:  validateRootArgs,
		Use:   "conscan",
		Short: "Scan a container image for vulnerabilities, exposed secrets, inefficient file storage, installed packages and suggest container image security best practices",
		Long:  rootCMDUsage,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				fmt.Printf("%s %s\n", identiifcaton.Name, identiifcaton.Version)
			}
		},
	}

	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show Version")

	return rootCmd
}

func validateRootArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 && cmd.Flags().NFlag() == 0 {
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
	}

	return nil
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.conscan.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
