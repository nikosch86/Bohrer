// Package fileutil provides utility functions for file operations
package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileWithDir creates the directory structure if needed and writes the file
// This function combines os.MkdirAll and os.WriteFile to reduce code duplication
func WriteFileWithDir(path string, data []byte, perm os.FileMode) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the file
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	return nil
}

// WriteAtomicFile writes data to a file atomically by writing to a temp file first
// then renaming it. This prevents partial writes from being visible.
func WriteAtomicFile(path string, data []byte, perm os.FileMode) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write to temporary file first
	tempFile := path + ".tmp"
	if err := os.WriteFile(tempFile, data, perm); err != nil {
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Rename temp file to target (atomic operation on most filesystems)
	if err := os.Rename(tempFile, path); err != nil {
		// Clean up temp file on error
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}