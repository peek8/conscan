/*
 * Copyright (c) 2026 peek8.io
 *
 * Created Date: Tuesday, January 6th 2026, 9:09:27 am
 * Author: Md. Asraful Haque
 *
 */

package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/peek8/conscan/pkg/models"
)

type Uploader struct {
	URL         string
	ContentType string
}

func (up Uploader) Write(_ context.Context, report models.ScanReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", up.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", up.ContentType)

	res, err := http.DefaultClient.Do(req)

	if res.StatusCode >= 400 {
		return fmt.Errorf("upload failed with status: %s", res.Status)
	}

	if err == nil && res.StatusCode < 300 {
		fmt.Fprintf(io.Writer(os.Stderr), "[✔] Upload Report finished\n")
	}

	return err
}
