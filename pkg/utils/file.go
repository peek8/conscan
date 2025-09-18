/*
 * Copyright (c) 2025 peek8.io
 *
 * Created Date: Wednesday, September 17th 2025, 10:26:13 am
 * Author: Md. Asraful Haque
 *
 */

package utils

import (
	"os"
	"strings"
)

type TempDirGenerator struct {
	prefix   string
	location string
}

func NewTempDirGenerator(name string) *TempDirGenerator {
	return &TempDirGenerator{
		prefix: name,
	}
}

func (t *TempDirGenerator) GetOrCreateRootLocation() (string, error) {
	if t.location == "" {
		location, err := os.MkdirTemp("", t.prefix+"-")
		if err != nil {
			return "", err
		}

		t.location = location
	}
	return t.location, nil
}

// NewDirectory creates a new temp dir within the generators prefix temp dir.
func (t *TempDirGenerator) NewDirectory(name ...string) (string, error) {
	location, err := t.GetOrCreateRootLocation()
	if err != nil {
		return "", err
	}

	return os.MkdirTemp(location, strings.Join(name, "-")+"-")
}

// Cleanup deletes all temp dirs created by this generator and any child generator.
func (t *TempDirGenerator) Cleanup() error {
	if t.location != "" {
		if err := os.RemoveAll(t.location); err != nil {
			return err
		}
	}

	return nil
}
