package webui

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"bohrer-go/internal/logger"
)

// Common HTTP errors
var (
	ErrMethodNotAllowed = &HTTPErr{Code: http.StatusMethodNotAllowed, Message: "Method not allowed"}
	ErrBadRequest       = &HTTPErr{Code: http.StatusBadRequest, Message: "Bad request"}
	ErrInternalServer   = &HTTPErr{Code: http.StatusInternalServerError, Message: "Internal server error"}
	ErrUnauthorized     = &HTTPErr{Code: http.StatusUnauthorized, Message: "Unauthorized"}
	ErrNotFound         = &HTTPErr{Code: http.StatusNotFound, Message: "Not found"}
	ErrConflict         = &HTTPErr{Code: http.StatusConflict, Message: "Conflict"}
)

// HTTPErr represents an HTTP error with status code and message
type HTTPErr struct {
	Code    int
	Message string
}

func (e *HTTPErr) Error() string {
	return e.Message
}

// HTTPError writes an error response based on the error type
func HTTPError(w http.ResponseWriter, err error) {
	var httpErr *HTTPErr
	if errors.As(err, &httpErr) {
		http.Error(w, httpErr.Message, httpErr.Code)
		return
	}
	// Default to internal server error
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

// HTTPErrorf writes a formatted error response
func HTTPErrorf(w http.ResponseWriter, code int, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	http.Error(w, message, code)
}

// RequireMethod checks if the request method is allowed
func RequireMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	HTTPError(w, ErrMethodNotAllowed)
	return false
}

// ParseFormData parses form data and handles errors
func ParseFormData(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		logger.Debugf("Failed to parse form: %v", err)
		HTTPErrorf(w, http.StatusBadRequest, "Failed to parse form")
		return err
	}
	return nil
}

// RequireFormFields checks if required form fields are present and non-empty
func RequireFormFields(w http.ResponseWriter, r *http.Request, fields ...string) error {
	for _, field := range fields {
		if value := r.FormValue(field); value == "" {
			err := fmt.Errorf("%s is required", field)
			HTTPErrorf(w, http.StatusBadRequest, "%s is required", field)
			return err
		}
	}
	return nil
}

// ExtractPathParam extracts a parameter from the URL path
func ExtractPathParam(w http.ResponseWriter, r *http.Request, basePath string) (string, error) {
	// Remove trailing slash from base path for comparison
	basePath = strings.TrimSuffix(basePath, "/")
	
	// Get the parameter part
	param := strings.TrimPrefix(r.URL.Path, basePath)
	param = strings.TrimPrefix(param, "/")
	
	if param == "" {
		err := fmt.Errorf("parameter required in path")
		HTTPErrorf(w, http.StatusBadRequest, "Parameter required")
		return "", err
	}
	
	// If there are more slashes, just take the first part
	if idx := strings.Index(param, "/"); idx > 0 {
		param = param[:idx]
	}
	
	return param, nil
}

// LogAndHTTPError logs an error and sends an HTTP error response
func LogAndHTTPError(w http.ResponseWriter, format string, args ...interface{}) {
	logger.Errorf(format, args...)
	HTTPError(w, ErrInternalServer)
}

// LogAndHTTPErrorf logs an error and sends a formatted HTTP error response
func LogAndHTTPErrorf(w http.ResponseWriter, code int, logFormat string, httpFormat string, args ...interface{}) {
	logger.Errorf(logFormat, args...)
	HTTPErrorf(w, code, httpFormat, args...)
}