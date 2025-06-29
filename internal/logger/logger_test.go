package logger

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestSetLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"DEBUG", DEBUG},
		{"debug", DEBUG},
		{"INFO", INFO},
		{"info", INFO},
		{"WARN", WARN},
		{"warn", WARN},
		{"WARNING", WARN},
		{"ERROR", ERROR},
		{"error", ERROR},
		{"FATAL", FATAL},
		{"fatal", FATAL},
		{"INVALID", INFO}, // Should default to INFO
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			SetLevel(test.input)
			if currentLevel != test.expected {
				t.Errorf("SetLevel(%s): expected %v, got %v", test.input, test.expected, currentLevel)
			}
		})
	}
}

func TestIsDebugEnabled(t *testing.T) {
	// Test debug enabled
	SetLevel("DEBUG")
	if !IsDebugEnabled() {
		t.Error("IsDebugEnabled should return true when level is DEBUG")
	}

	// Test debug disabled
	SetLevel("INFO")
	if IsDebugEnabled() {
		t.Error("IsDebugEnabled should return false when level is INFO")
	}
}

func TestLogLevels(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Set to DEBUG level to capture all messages
	SetLevel("DEBUG")

	tests := []struct {
		name     string
		logFunc  func()
		expected string
	}{
		{
			name:     "Debug",
			logFunc:  func() { Debug("debug message") },
			expected: "[DEBUG] debug message",
		},
		{
			name:     "Info",
			logFunc:  func() { Info("info message") },
			expected: "[INFO] info message",
		},
		{
			name:     "Warn",
			logFunc:  func() { Warn("warn message") },
			expected: "[WARN] warn message",
		},
		{
			name:     "Error",
			logFunc:  func() { Error("error message") },
			expected: "[ERROR] error message",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf.Reset()
			test.logFunc()
			output := buf.String()
			if !strings.Contains(output, test.expected) {
				t.Errorf("Expected log to contain %q, got %q", test.expected, output)
			}
		})
	}
}

func TestLogFiltering(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Set to ERROR level - should only show ERROR and FATAL
	SetLevel("ERROR")

	// These should not appear in output
	Debug("debug message")
	Info("info message")
	Warn("warn message")

	// This should appear
	Error("error message")

	output := buf.String()

	// Check that lower level messages are filtered out
	if strings.Contains(output, "[DEBUG]") {
		t.Error("DEBUG message should be filtered out at ERROR level")
	}
	if strings.Contains(output, "[INFO]") {
		t.Error("INFO message should be filtered out at ERROR level")
	}
	if strings.Contains(output, "[WARN]") {
		t.Error("WARN message should be filtered out at ERROR level")
	}

	// Check that ERROR message appears
	if !strings.Contains(output, "[ERROR] error message") {
		t.Error("ERROR message should appear at ERROR level")
	}
}

func TestFormattedLogging(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	SetLevel("DEBUG")

	tests := []struct {
		name     string
		logFunc  func()
		expected string
	}{
		{
			name:     "Debugf",
			logFunc:  func() { Debugf("formatted %s %d", "debug", 42) },
			expected: "[DEBUG] formatted debug 42",
		},
		{
			name:     "Infof",
			logFunc:  func() { Infof("formatted %s %d", "info", 42) },
			expected: "[INFO] formatted info 42",
		},
		{
			name:     "Warnf",
			logFunc:  func() { Warnf("formatted %s %d", "warn", 42) },
			expected: "[WARN] formatted warn 42",
		},
		{
			name:     "Errorf",
			logFunc:  func() { Errorf("formatted %s %d", "error", 42) },
			expected: "[ERROR] formatted error 42",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			buf.Reset()
			test.logFunc()
			output := buf.String()
			if !strings.Contains(output, test.expected) {
				t.Errorf("Expected log to contain %q, got %q", test.expected, output)
			}
		})
	}
}

func TestGetLevel(t *testing.T) {
	// Test getting current level
	SetLevel("WARN")
	if GetLevel() != WARN {
		t.Errorf("GetLevel(): expected %v, got %v", WARN, GetLevel())
	}

	SetLevel("DEBUG")
	if GetLevel() != DEBUG {
		t.Errorf("GetLevel(): expected %v, got %v", DEBUG, GetLevel())
	}
}

// Note: Testing Fatal/Fatalf is complex since they call os.Exit(1)
// The functions are tested indirectly through integration tests
