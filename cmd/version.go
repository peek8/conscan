/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Monday, September 15th 2025, 3:16:37 pm
 * Author: Md. Asraful Haque
 *
 */

package cmd

import (
	"bytes"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

type runtimeInfo struct {
	Identification
	GoVersion string `json:"goVersion,omitempty"` // go runtime version at build-time
	Compiler  string `json:"compiler,omitempty"`  // compiler used at build-time
	Platform  string `json:"platform,omitempty"`  // GOOS and GOARCH at build-time
}

// VersionCommand create the version command, Inspired from anchore/clio
func VersionCommand(id Identification) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "show version information",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			info := runtimeInfo{
				Identification: id,
				GoVersion:      runtime.Version(),
				Compiler:       runtime.Compiler,
				Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			}

			value := versionInfo(info)
			fmt.Print(value)
		},
	}

	//flags := cmd.Flags()
	//flags.StringVarP(&format, "output", "o", "text", "the format to show the results (allowable: [text json])")

	return cmd
}

func versionInfo(info runtimeInfo) string {
	buf := &bytes.Buffer{}

	pad := 15
	appendLine(buf, "Application", pad, info.Name)
	appendLine(buf, "Version", pad, info.Identification.Version)
	appendLine(buf, "BuildDate", pad, info.BuildDate)
	appendLine(buf, "GitCommit", pad, info.GitCommit)
	appendLine(buf, "Platform", pad, info.Platform)
	appendLine(buf, "GoVersion", pad, info.GoVersion)
	appendLine(buf, "Compiler", pad, info.Compiler)

	return buf.String()
}

func appendLine(buf *bytes.Buffer, title string, width int, value any) {
	if fmt.Sprintf("%v", value) == "" {
		return
	}

	_, _ = fmt.Fprintf(buf, "%-*s %v\n", width, title+":", value)
}
