/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package main

import "github.com/peek8/conscan/cmd"

const (
	applicationName = "conscan"
)

// to be overwritten by -ldflags
var (
	version   = "dev"
	gitCommit = "none"
	buildDate = "unknown"
)

func main() {
	cmd.Execute(cmd.Identification{
		Name:      applicationName,
		Version:   version,
		GitCommit: gitCommit,
		BuildDate: buildDate,
	})
}
