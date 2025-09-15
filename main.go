/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package main

import "peek8.io/conscan/cmd"

const (
	applicationName = "conscan"
)

// to be overwritten by -ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.Execute(cmd.Identification{
		Name:      applicationName,
		Version:   version,
		GitCommit: commit,
		BuildDate: date,
	})
}
