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
		Use:   "conscan",
		Short: "Scanner for vulnerabilities in container images as well as for configuration issues and hard-coded secrets",
		Long: `Usage:
	conscan [command] target`,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		Run: func(cmd *cobra.Command, args []string) {
			if showVersion {
				fmt.Printf("%s %s\n", identiifcaton.Name, identiifcaton.Version)
			}
		},
	}

	rootCmd.Flags().BoolVarP(&showVersion, "Version", "v", false, "Show Version")

	return rootCmd
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
