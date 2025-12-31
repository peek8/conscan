/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, September 2nd 2025, 5:19:21 pm
 * Author: Md. Asraful Haque
 *
 * -----
 * Last Modified: Tuesday, 2nd September 2025 5:19:22 pm
 * Modified By: Md. Asraful Haque
 * -----
 */

// Package report provides staff for report generation
package report

import (
	"context"
	"io"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/peek8/conscan/pkg/models"
	"golang.org/x/xerrors"
)

type Writer interface {
	Write(context.Context, models.ScanReport) error
}

func Write(ctx context.Context, report models.ScanReport, option models.ScanOptions) (err error) {
	output, cleanup, err := OutputWriter(option)
	if err != nil {
		return xerrors.Errorf("failed to create a file: %w", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			err = multierror.Append(err, cerr)
		}
	}()

	var writer Writer
	switch option.Format {
	case models.FormatJson:
		writer = JsonWriter{Output: output}
	case models.FormatTable:
		writer = TableWriter{Output: output}
	case models.FormatHtml:
		writer = HtmlWriter{Output: output}
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	if err = writer.Write(ctx, report); err != nil {
		return xerrors.Errorf("failed to write results: %w", err)
	}

	return nil
}

// OutputWriter returns an output writer.
// If the output file is not specified, it returns os.Stdout.
func OutputWriter(opts models.ScanOptions) (io.Writer, func() error, error) {
	cleanup := func() error { return nil }

	if opts.OutputFile == "" {
		return os.Stdout, cleanup, nil
	}

	f, err := os.Create(opts.OutputFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to create output file: %w", err)
	}
	return f, f.Close, nil
}
