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
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/peek8/conscan/pkg/models"
	"github.com/peek8/conscan/pkg/utils"
	"github.com/samber/lo"
)

const (
	maxRowCount = 25
)

var severityColors = map[string]color.Attribute{
	models.SeverityNameCritical: color.FgRed,
	models.SeverityNameHigh:     color.FgHiMagenta,
	models.SeverityNameMedium:   color.FgYellow,
	models.SeverityNameLow:      color.FgGreen,
	models.SeverityNameUnknown:  color.FgCyan,
	//models.SeverityNameNegligible:  color.FgHiBlue,
}

var cisLevelColors = map[string]color.Attribute{
	"FATAL":  color.FgRed,
	"WARN":   color.FgHiMagenta,
	"INFO":   color.FgYellow,
	"SKIP":   color.FgGreen,
	"IGNORE": color.FgCyan,
	"PASS":   color.FgCyan,
}

type TableWriter struct {
	Output io.Writer
}

type Renderer interface {
	Render(models.ScanReport) error
}

func (tw TableWriter) Write(_ context.Context, report models.ScanReport) error {
	buf := bytes.NewBuffer([]byte{})
	renderers := tw.getRenderers(buf, report)
	for _, renderer := range renderers {
		err := renderer.Render(report)
		if err != nil {
			return err
		}
	}

	fmt.Fprint(tw.Output, buf.String())

	return nil
}

func (tw TableWriter) getRenderers(buf io.Writer, report models.ScanReport) []Renderer {
	renderers := []Renderer{
		HeaderRenderer{buf: buf},
	}

	renderers = utils.AppendIf(lo.IsNotNil(report.VulnerabilitySummary), renderers, Renderer(VulnerabilitySummaryRenderer{buf: buf}))
	renderers = utils.AppendIf(utils.IsNotEmptyArray(report.Vulnerabilities), renderers, Renderer(VulnerabilitiesRenderer{buf: buf}))
	renderers = utils.AppendIf(utils.IsNotEmptyArray(report.Secrets), renderers, Renderer(SecretsRenderer{buf: buf}))
	renderers = utils.AppendIf(lo.IsNotNil(report.CISScans), renderers, Renderer(CISRenderer{buf: buf}))
	renderers = utils.AppendIf(lo.IsNotNil(report.StorageAnalysis), renderers, Renderer(StorageRenderer{buf: buf}))
	renderers = utils.AppendIf(lo.IsNotNil(report.SBOMs), renderers, Renderer(SBOMRenderer{buf: buf}))

	return renderers
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
	t.AppendRow(table.Row{"Vulnerabilities", utils.EitherOrFunc(lo.IsNotNil(report.VulnerabilitySummary), func() string { return strconv.Itoa(report.VulnerabilitySummary.TotalCount) }, "-")})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Exposed Secrets", len(report.Secrets)})
	t.AppendSeparator()
	t.AppendRow(table.Row{"Installed Package/Software", utils.EitherOrFunc(lo.IsNotNil(report.SBOMs), func() string { return strconv.Itoa(len(report.SBOMs.Packages)) }, "-")})
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
	vulns := lo.Slice(report.Vulnerabilities, 0, maxRowCount)
	for _, vuln := range vulns {
		t.AppendRow(table.Row{
			vuln.PkgName, vuln.VulnerabilityID, getSeverityColoredText(vuln.Severity), getColored(vuln.InstalledVersion, color.FgMagenta), getColored(vuln.FixedVersion, color.FgGreen), vr.getVulnerabilityDescription(vuln),
		})
		t.AppendSeparator()
	}

	t.Render()
	if len(report.Vulnerabilities) > maxRowCount {
		addInfo(vr.buf, fmt.Sprintf("Showing %d Vulnerabilites from total %d vulnerabilites for the sake of readability at console, to view all the vulnerabilites use other format ie `json` or `html`.", maxRowCount, len(report.Vulnerabilities)))
	}

	return nil
}

func (vr VulnerabilitiesRenderer) getVulnerabilityDescription(vuln models.DetectedVulnerability) string {
	desc := utils.EitherOr(len(vuln.Title) > 0, vuln.Title, vuln.Description)
	sourceUrl := utils.IfEmptyStr(vuln.DataSourceURL, fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", vuln.VulnerabilityID))

	return fmt.Sprintf("%s....\n%s", wrapText(desc, 100), getColored(sourceUrl, color.FgBlue))
}

type SecretsRenderer struct {
	buf io.Writer
}

func (sr SecretsRenderer) Render(report models.ScanReport) error {
	addHeader(sr.buf, "Exposed Secrets:")
	addInfo(sr.buf, fmt.Sprintf("Total Exposed Secrets: %d", len(report.Secrets)))

	// If there are no secrets no need to show the tables
	if len(report.Secrets) == 0 {
		return nil
	}

	t := newTable(sr.buf)
	t.AppendHeader(table.Row{"Location", "Title", "Category", "Content", "Severity", "Description"})
	for _, sec := range report.Secrets {
		t.AppendRow(table.Row{
			getSecretLocation(sec), sec.Title, sec.Category, sec.Content, getSeverityColoredText(sec.Severity), sec.Description,
		})
		t.AppendSeparator()
	}

	t.Render()

	return nil
}

func getSecretLocation(sec models.DetectedPresSecret) string {
	if sec.LocationType == models.LocationTypeFileSystem {
		return fmt.Sprintf("%s:%d:%d", sec.Target, sec.StartLine, sec.EndLine)
	}

	return "Environment Variables"
}

type SBOMRenderer struct {
	buf io.Writer
}

func (sbr SBOMRenderer) Render(report models.ScanReport) error {
	addHeader(sbr.buf, "Installed Packages/Software: ")
	addInfo(sbr.buf, fmt.Sprintf("Total Packages found: %d", len(report.SBOMs.Packages)))

	t := newTable(sbr.buf)

	t.AppendHeader(table.Row{"Name", "Version", "License", "Description"})

	packages := lo.Slice(report.SBOMs.Packages, 0, maxRowCount)
	for _, pkg := range packages {
		t.AppendRow(table.Row{
			pkg.PackageName, pkg.PackageVersion, pkg.PackageLicenseDeclared, wrapText(pkg.PackageDescription, 100),
		})
		t.AppendSeparator()
	}

	t.Render()
	if len(report.SBOMs.Packages) > maxRowCount {
		addInfo(sbr.buf, fmt.Sprintf("Showing %d packages from total %d packages for the sake of readability at console, to view all the packages use other format ie `json` or `html`.", maxRowCount, len(report.SBOMs.Packages)))
	}

	return nil
}

type CISRenderer struct {
	buf io.Writer
}

func (cr CISRenderer) Render(report models.ScanReport) error {
	addHeader(cr.buf, "CIS Benchmark Violations: ")

	t := newTable(cr.buf)

	t.AppendHeader(table.Row{"CIS ID", "Title", "Severity", "Description"})
	for _, cis := range report.CISScans.Details {
		t.AppendRow(table.Row{
			cis.Code, cis.Title, getCISLevelColoredText(cis.Level), wrapText(strings.Join(cis.Alerts, "\n"), 100),
		})
		t.AppendSeparator()
	}

	t.Render()

	return nil
}

type StorageRenderer struct {
	buf io.Writer
}

func (sr StorageRenderer) Render(report models.ScanReport) error {
	addHeader(sr.buf, "Storage Analysis:")
	addInfo(sr.buf, fmt.Sprintf("Efficiency: %.2f%%", report.StorageAnalysis.Efficiency))
	addInfo(sr.buf, fmt.Sprintf("Wasted Bytes: %s", report.StorageAnalysis.WastedBytesHuman))
	addInfo(sr.buf, fmt.Sprintf("User Wasted Percent: %.2f%%", report.StorageAnalysis.UserWastedPercent))

	addInfo(sr.buf, "Inefficient Files:")

	t := newTable(sr.buf)
	t.AppendHeader(table.Row{"Count", "Wasted Space", "File Path"})
	files := lo.Slice(report.StorageAnalysis.InefficientFiles, 0, maxRowCount)
	for _, ief := range files {
		t.AppendRow(table.Row{
			ief.Count, ief.WastedSpace, ief.FilePath,
		})
		t.AppendSeparator()
	}

	t.Render()
	if len(report.StorageAnalysis.InefficientFiles) > maxRowCount {
		addInfo(sr.buf, fmt.Sprintf("Showing %d Inefficient Files from total %d files for the sake of readability at console, to view all the Inefficient Files use other format ie `json` or `html`.", maxRowCount, len(report.StorageAnalysis.InefficientFiles)))
	}

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

func getCISLevelColoredText(severity string) string {
	severity = strings.ToUpper(severity)

	return getColoredBold(severity, cisLevelColors[severity])
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

func addInfo(buf io.Writer, text string) {
	info := getColored(text, color.FgCyan)

	fmt.Fprintln(buf, "\n"+info)
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
