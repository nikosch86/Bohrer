package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileWithDir(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(string) error
		path     string
		data     []byte
		perm     os.FileMode
		wantErr  bool
		errorMsg string
	}{
		{
			name: "write file to new directory",
			path: "new/dir/file.txt",
			data: []byte("test content"),
			perm: 0644,
			wantErr: false,
		},
		{
			name: "write file to existing directory",
			setup: func(dir string) error {
				return os.MkdirAll(filepath.Join(dir, "existing"), 0755)
			},
			path: "existing/file.txt",
			data: []byte("test content"),
			perm: 0644,
			wantErr: false,
		},
		{
			name: "write file with empty data",
			path: "empty/file.txt",
			data: []byte{},
			perm: 0644,
			wantErr: false,
		},
		{
			name: "write file with restricted permissions",
			path: "secure/key.pem",
			data: []byte("private key"),
			perm: 0600,
			wantErr: false,
		},
		{
			name: "write file to deeply nested directory",
			path: "a/b/c/d/e/f/file.txt",
			data: []byte("nested content"),
			perm: 0644,
			wantErr: false,
		},
		{
			name: "overwrite existing file",
			setup: func(dir string) error {
				path := filepath.Join(dir, "existing.txt")
				if err := os.MkdirAll(dir, 0755); err != nil {
					return err
				}
				return os.WriteFile(path, []byte("old content"), 0644)
			},
			path: "existing.txt",
			data: []byte("new content"),
			perm: 0644,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test
			tempDir := t.TempDir()
			fullPath := filepath.Join(tempDir, tt.path)

			// Run setup if provided
			if tt.setup != nil {
				if err := tt.setup(tempDir); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			// Test WriteFileWithDir
			err := WriteFileWithDir(fullPath, tt.data, tt.perm)

			// Check error
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteFileWithDir() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errorMsg != "" && err != nil {
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("WriteFileWithDir() error = %v, want error containing %v", err, tt.errorMsg)
				}
				return
			}

			// If no error expected, verify the file
			if !tt.wantErr {
				// Check if file exists
				info, err := os.Stat(fullPath)
				if err != nil {
					t.Errorf("Failed to stat created file: %v", err)
					return
				}

				// Check permissions (only check the permission bits we set)
				gotPerm := info.Mode().Perm()
				if gotPerm != tt.perm {
					t.Errorf("File permissions = %v, want %v", gotPerm, tt.perm)
				}

				// Check content
				content, err := os.ReadFile(fullPath)
				if err != nil {
					t.Errorf("Failed to read created file: %v", err)
					return
				}

				if string(content) != string(tt.data) {
					t.Errorf("File content = %q, want %q", string(content), string(tt.data))
				}
			}
		})
	}
}

func TestWriteFileWithDir_InvalidPath(t *testing.T) {
	// Skip this test if running as root or in environments where we can't test permission errors
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	// Try to write to a path where we don't have permission
	err := WriteFileWithDir("/root/test/file.txt", []byte("test"), 0644)
	if err == nil {
		t.Error("Expected error when writing to restricted path")
	}
}

func TestWriteFileWithDir_FileAsDirectory(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create a file where we'll try to create a directory
	blockingFile := filepath.Join(tempDir, "blocking")
	if err := os.WriteFile(blockingFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create blocking file: %v", err)
	}

	// Try to write a file that would require 'blocking' to be a directory
	err := WriteFileWithDir(filepath.Join(blockingFile, "subdir", "file.txt"), []byte("test"), 0644)
	if err == nil {
		t.Error("Expected error when parent path is a file")
	}
}

func TestWriteAtomicFile(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(string) error
		path     string
		data     []byte
		perm     os.FileMode
		wantErr  bool
	}{
		{
			name: "atomic write to new file",
			path: "atomic/file.json",
			data: []byte(`{"key": "value"}`),
			perm: 0644,
			wantErr: false,
		},
		{
			name: "atomic overwrite existing file",
			setup: func(dir string) error {
				path := filepath.Join(dir, "existing.json")
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					return err
				}
				return os.WriteFile(path, []byte(`{"old": "data"}`), 0644)
			},
			path: "existing.json",
			data: []byte(`{"new": "data"}`),
			perm: 0644,
			wantErr: false,
		},
		{
			name: "atomic write with restricted permissions",
			path: "secure/data.json",
			data: []byte(`{"secret": "value"}`),
			perm: 0600,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			fullPath := filepath.Join(tempDir, tt.path)

			if tt.setup != nil {
				if err := tt.setup(tempDir); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			err := WriteAtomicFile(fullPath, tt.data, tt.perm)

			if (err != nil) != tt.wantErr {
				t.Errorf("WriteAtomicFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify file exists and has correct content
				content, err := os.ReadFile(fullPath)
				if err != nil {
					t.Errorf("Failed to read file: %v", err)
					return
				}

				if string(content) != string(tt.data) {
					t.Errorf("File content = %q, want %q", string(content), string(tt.data))
				}

				// Verify no temp files are left
				tempFile := fullPath + ".tmp"
				if _, err := os.Stat(tempFile); err == nil {
					t.Error("Temporary file was not cleaned up")
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || len(substr) < len(s) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}