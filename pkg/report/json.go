/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Tuesday, September 2nd 2025, 5:28:41 pm
 * Author: Md. Asraful Haque
 *
 * -----
 * Last Modified: Tuesday, 2nd September 2025 5:28:41 pm
 * Modified By: Md. Asraful Haque
 * -----
 */

package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/xerrors"
	"peek8.io/conscan/pkg/models"
)

type JsonWriter struct {
	Output io.Writer
}

func (jw JsonWriter) Write(_ context.Context, report models.ScanReport) error {
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal json: %w", err)
	}

	if _, err = fmt.Fprintln(jw.Output, string(output)); err != nil {
		return xerrors.Errorf("failed to write json: %w", err)
	}

	return nil
}
