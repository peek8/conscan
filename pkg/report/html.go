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

type HtmlWriter struct {
	Output io.Writer
}

func (hw HtmlWriter) Write(_ context.Context, report models.ScanReport) error {
	tmpl := hw.newTemplate()
	err := tmpl.Execute(hw.Output, report)

	return err
}

func (hw HtmlWriter) newTemplate() *template.Template {
	tmpl, err := template.New("html-report").Funcs(funcMap).Parse(htmlReportTemplate)

	utils.ExitOnError(err)

	return tmpl

}

var funcMap = template.FuncMap{
	"getTitle":              getTitle,
	"getCvssScore":          getCvssScore,
	"toLower":               toLower,
	"emptyValuePlaceholder": emptyValuePlaceholder,
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

func emptyValuePlaceholder(s string) string {
	if s != "" {
		return s
	}

	return "-"
}
