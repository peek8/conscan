/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Saturday, September 6th 2025, 4:51:55 pm
 * Author: Md. Asraful Haque
 *
 */

package report

import (
	"context"
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/samber/lo"
	"peek8.io/conscan/pkg/models"
	"peek8.io/conscan/pkg/utils"
)

//go:embed templates/container-dashboard.html
var htmlReportTemplate string

//go:embed templates/container-dashboard-classic.html
var htmlReportTemplateClassic string

type HtmlWriter struct {
	Output io.Writer
}

func (hw HtmlWriter) Write(_ context.Context, report models.ScanReport) error {
	tmpl := hw.newTemplate()
	err := tmpl.Execute(hw.Output, report)

	return err
}

func (hw HtmlWriter) newTemplate() *template.Template {
	tmpl, err := template.New("html-report").Funcs(funcMap).Parse(htmlReportTemplateClassic)

	utils.ExitOnError(err)

	return tmpl

}

var funcMap = template.FuncMap{
	"getTitle":              getTitle,
	"getCvssScore":          getCvssScore,
	"toLower":               toLower,
	"emptyValuePlaceholder": emptyValuePlaceholder,
	"getSecretLocation":     getSecretLocation,
	"htmlLineBreak":         htmlLineBreak,
	"slicesToHtmlLineBreak": slicesToHtmlLineBreak,
	"twoDecimalPercentage":  twoDecimalPercentage,
}

func getTitle(vuln models.DetectedVulnerability) string {
	return utils.IfEmptyStr(vuln.Title, lo.Ellipsis(vuln.Description, 100))
}

func getCvssScore(vuln models.DetectedVulnerability) string {
	return utils.EitherOr(vuln.CvssScore > 0, fmt.Sprintf("%.2f", vuln.CvssScore), "Unknown")
}

func toLower(s string) string {
	return strings.ToLower(s)
}

func htmlLineBreak(text string) template.HTML {
	return template.HTML(strings.ReplaceAll(strings.TrimSpace(text), "\n", "<br>"))
}

func slicesToHtmlLineBreak(text []string) template.HTML {
	return template.HTML(strings.Join(text, "<br>"))
}

func twoDecimalPercentage(num float64) string {
	return fmt.Sprintf("%.2f%%", num)
}

func emptyValuePlaceholder(s string) string {
	if s != "" {
		return s
	}

	return "-"
}
