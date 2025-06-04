package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel represents the severity of log messages
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var (
	currentLevel = INFO
	levelNames   = map[LogLevel]string{
		DEBUG: "DEBUG",
		INFO:  "INFO",
		WARN:  "WARN",
		ERROR: "ERROR",
		FATAL: "FATAL",
	}
)

func init() {
	// Set log level from environment variable
	if levelStr := os.Getenv("LOG_LEVEL"); levelStr != "" {
		SetLevel(levelStr)
	}
}

// SetLevel sets the logging level from a string
func SetLevel(level string) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		currentLevel = DEBUG
	case "INFO":
		currentLevel = INFO
	case "WARN", "WARNING":
		currentLevel = WARN
	case "ERROR":
		currentLevel = ERROR
	case "FATAL":
		currentLevel = FATAL
	default:
		log.Printf("Unknown log level: %s, using INFO", level)
		currentLevel = INFO
	}
}

// GetLevel returns the current log level
func GetLevel() LogLevel {
	return currentLevel
}

// logf formats and logs a message at the specified level
func logf(level LogLevel, format string, args ...interface{}) {
	if level < currentLevel {
		return
	}

	message := fmt.Sprintf(format, args...)
	levelName := levelNames[level]
	log.Printf("[%s] %s", levelName, message)

	if level == FATAL {
		os.Exit(1)
	}
}

// log logs a message at the specified level without formatting
func logMessage(level LogLevel, args ...interface{}) {
	if level < currentLevel {
		return
	}

	message := fmt.Sprint(args...)
	levelName := levelNames[level]
	log.Printf("[%s] %s", levelName, message)

	if level == FATAL {
		os.Exit(1)
	}
}

// Debug logs a debug message
func Debug(args ...interface{}) {
	logMessage(DEBUG, args...)
}

// Debugf logs a formatted debug message
func Debugf(format string, args ...interface{}) {
	logf(DEBUG, format, args...)
}

// Info logs an info message
func Info(args ...interface{}) {
	logMessage(INFO, args...)
}

// Infof logs a formatted info message
func Infof(format string, args ...interface{}) {
	logf(INFO, format, args...)
}

// Warn logs a warning message
func Warn(args ...interface{}) {
	logMessage(WARN, args...)
}

// Warnf logs a formatted warning message
func Warnf(format string, args ...interface{}) {
	logf(WARN, format, args...)
}

// Error logs an error message
func Error(args ...interface{}) {
	logMessage(ERROR, args...)
}

// Errorf logs a formatted error message
func Errorf(format string, args ...interface{}) {
	logf(ERROR, format, args...)
}

// Fatal logs a fatal message and exits
func Fatal(args ...interface{}) {
	logMessage(FATAL, args...)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, args ...interface{}) {
	logf(FATAL, format, args...)
}

// IsDebugEnabled returns true if debug logging is enabled
func IsDebugEnabled() bool {
	return currentLevel <= DEBUG
}
