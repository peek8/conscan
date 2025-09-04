/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Wednesday, September 3rd 2025, 3:26:49 pm
 * Author: Md. Asraful Haque
 *
 */

package report

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/utils"
)

var severityColors = map[string]color.Attribute{
	models.SeverityNameCritical: color.FgRed,
	models.SeverityNameHigh:     color.FgHiMagenta,
	models.SeverityNameMedium:   color.FgYellow,
	models.SeverityNameLow:      color.FgGreen,
	models.SeverityNameUnknown:  color.FgCyan,
}

type TableWriter struct {
	Output io.Writer
}

type Renderer interface {
	Render(models.ScanReport) error
}

func (tw TableWriter) Write(_ context.Context, report models.ScanReport) error {
	buf := bytes.NewBuffer([]byte{})
	renderers := []Renderer{
		HeaderRenderer{buf: buf},
		VulnerabilitySummaryRenderer{buf: buf},
		VulnerabilitiesRenderer{buf: buf},
		SBOMRenderer{buf: buf},
	}

	for _, renderer := range renderers {
		err := renderer.Render(report)
		if err != nil {
			return err
		}
	}

	fmt.Fprint(tw.Output, buf.String())

	return nil
}

type HeaderRenderer struct {
	buf io.Writer
}

func (hr HeaderRenderer) Render(report models.ScanReport) error {
	// Add some ascii banner using https://github.com/common-nighthawk/go-figure
	addHeader(hr.buf, "ConScan Report Summary:")

	t := newTable(hr.buf)

	t.AppendRow(table.Row{"Scanned Image", report.ArtifactName})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Vulnerabilities", report.VulnerabilitySummary.TotalCount})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Exposed Secrets", len(report.Secrets)})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Installed Package/Software", len(report.SBOMs.Packages)})
	t.AppendSeparator()

	t.Render()

	return nil
}

type VulnerabilitySummaryRenderer struct {
	buf io.Writer
}

func (vsr VulnerabilitySummaryRenderer) Render(report models.ScanReport) error {
	addHeader(vsr.buf, "Vulnerability Summary:")
	t := newTable(vsr.buf)

	t.AppendHeader(table.Row{"Vulnerability Severity", "Count"})
	t.AppendRow(table.Row{getSeverityColoredText(models.SeverityNameCritical), report.VulnerabilitySummary.CriticalCount})
	t.AppendSeparator()
	t.AppendRow(table.Row{getSeverityColoredText(models.SeverityNameHigh), report.VulnerabilitySummary.HighCount})
	t.AppendSeparator()
	t.AppendRow(table.Row{getSeverityColoredText(models.SeverityNameMedium), report.VulnerabilitySummary.MediumCount})
	t.AppendSeparator()
	t.AppendRow(table.Row{getSeverityColoredText(models.SeverityNameLow), report.VulnerabilitySummary.LowCount})
	t.AppendSeparator()
	t.AppendRow(table.Row{getSeverityColoredText(models.SeverityNameUnknown), report.VulnerabilitySummary.UnknowsCount})
	t.AppendSeparator()

	t.Render()

	return nil
}

type VulnerabilitiesRenderer struct {
	buf io.Writer
}

func (vr VulnerabilitiesRenderer) Render(report models.ScanReport) error {
	addHeader(vr.buf, "Vulnerabilities:")

	t := newTable(vr.buf)
	t.AppendHeader(table.Row{"Library", "Vulnerability", "Severity", "Installed Version", "Fixed Version", "Description"})
	for _, vuln := range report.Vulnerabilities {
		t.AppendRow(table.Row{
			vuln.PkgName, vuln.VulnerabilityID, getSeverityColoredText(vuln.Severity), getColored(vuln.InstalledVersion, color.FgMagenta), getColored(vuln.FixedVersion, color.FgGreen), vr.getVulnerabilityDescription(vuln),
		})
		t.AppendSeparator()
	}

	t.Render()

	return nil
}

func (vr VulnerabilitiesRenderer) getVulnerabilityDescription(vuln models.DetectedVulnerability) string {
	desc := utils.EitherOr(len(vuln.Title) > 0, vuln.Title, vuln.Description)

	url := getColored(fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", vuln.VulnerabilityID), color.FgBlue)

	return fmt.Sprintf("%s....\n%s", wrapText(desc, 100), url)
}

type SecretsRenderer struct {
	buf io.Writer
}

func (sr SecretsRenderer) Render(report models.ScanReport) error {
	t := newTable(sr.buf)

	t.Render()

	return nil
}

type SBOMRenderer struct {
	buf io.Writer
}

func (sbr SBOMRenderer) Render(report models.ScanReport) error {
	addHeader(sbr.buf, "Installed Packages/Software: ")

	t := newTable(sbr.buf)

	t.AppendHeader(table.Row{"Name", "Version", "License", "Description"})
	for _, pkg := range report.SBOMs.Packages {
		t.AppendRow(table.Row{
			pkg.PackageName, pkg.PackageVersion, pkg.PackageLicenseDeclared, wrapText(pkg.PackageDescription, 100),
		})
		t.AppendSeparator()
	}

	t.Render()

	return nil
}

func newTable(out io.Writer) table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(out)

	//t.SetStyle(table.StyleBold)
	t.Style().Box = table.StyleBoxLight

	return t
}

func getSeverityColoredText(severity string) string {
	severity = strings.ToUpper(severity)

	return getColoredBold(severity, severityColors[severity])
}

func getColored(text string, colors ...color.Attribute) string {
	col := color.New(colors...)
	return col.Sprint(text)
}

func getColoredBold(text string, colors ...color.Attribute) string {
	cols := append(colors, color.Bold)
	return getColored(text, cols...)
}

func getHeader1(text string) string {
	return getColored(strings.ToUpper(text), color.Bold, color.Underline, color.FgHiYellow)
}

func addHeader(buf io.Writer, text string) {
	header := getHeader1(text)

	fmt.Fprintln(buf, "\n"+header)
}

func wrapText(text string, lineLen int) string {
	if len(text) <= lineLen {
		return text
	}

	var b strings.Builder
	for i := 0; i < len(text); i += lineLen {
		end := i + lineLen
		if end > len(text) {
			end = len(text)
		}
		b.WriteString(text[i:end])
		if end < len(text) {
			b.WriteString("\n")
		}
	}

	return b.String()
}
