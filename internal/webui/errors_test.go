package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "method not allowed",
			err:            ErrMethodNotAllowed,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "bad request",
			err:            ErrBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Bad request",
		},
		{
			name:           "internal server error",
			err:            ErrInternalServer,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			HTTPError(rr, tt.err)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			body := strings.TrimSpace(rr.Body.String())
			if body != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
			}
		})
	}
}

func TestHTTPErrorf(t *testing.T) {
	rr := httptest.NewRecorder()
	HTTPErrorf(rr, http.StatusBadRequest, "Invalid parameter: %s", "test")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}

	expectedBody := "Invalid parameter: test"
	body := strings.TrimSpace(rr.Body.String())
	if body != expectedBody {
		t.Errorf("Expected body %q, got %q", expectedBody, body)
	}
}

func TestRequireMethod(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		allowedMethods []string
		shouldPass     bool
	}{
		{
			name:           "GET allowed",
			method:         "GET",
			allowedMethods: []string{"GET"},
			shouldPass:     true,
		},
		{
			name:           "POST not allowed",
			method:         "POST",
			allowedMethods: []string{"GET"},
			shouldPass:     false,
		},
		{
			name:           "Multiple methods allowed",
			method:         "POST",
			allowedMethods: []string{"GET", "POST"},
			shouldPass:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/test", nil)
			rr := httptest.NewRecorder()

			result := RequireMethod(rr, req, tt.allowedMethods...)

			if tt.shouldPass && !result {
				t.Error("Expected RequireMethod to return true")
			}
			if !tt.shouldPass && result {
				t.Error("Expected RequireMethod to return false")
			}

			if !tt.shouldPass && rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
			}
		})
	}
}

func TestParseFormData(t *testing.T) {
	tests := []struct {
		name        string
		formData    string
		contentType string
		shouldError bool
	}{
		{
			name:        "Valid form data",
			formData:    "key=value&another=test",
			contentType: "application/x-www-form-urlencoded",
			shouldError: false,
		},
		{
			name:        "Empty form data",
			formData:    "",
			contentType: "application/x-www-form-urlencoded",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", tt.contentType)
			rr := httptest.NewRecorder()

			err := ParseFormData(rr, req)

			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if err == nil && tt.formData != "" && strings.Contains(tt.formData, "key=value") && req.Form.Get("key") != "value" {
				t.Error("Form not parsed correctly")
			}
		})
	}
}

func TestRequireFormFields(t *testing.T) {
	tests := []struct {
		name        string
		formData    string
		required    []string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "All fields present",
			formData:    "username=test&password=secret",
			required:    []string{"username", "password"},
			shouldError: false,
		},
		{
			name:        "Missing field",
			formData:    "username=test",
			required:    []string{"username", "password"},
			shouldError: true,
			errorMsg:    "password is required",
		},
		{
			name:        "Empty field",
			formData:    "username=test&password=",
			required:    []string{"username", "password"},
			shouldError: true,
			errorMsg:    "password is required",
		},
		{
			name:        "Multiple missing fields",
			formData:    "",
			required:    []string{"username", "password"},
			shouldError: true,
			errorMsg:    "username is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.ParseForm()
			rr := httptest.NewRecorder()

			err := RequireFormFields(rr, req, tt.required...)

			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if tt.shouldError {
				body := strings.TrimSpace(rr.Body.String())
				if !strings.Contains(body, tt.errorMsg) {
					t.Errorf("Expected error message containing %q, got %q", tt.errorMsg, body)
				}
			}
		})
	}
}

func TestExtractPathParam(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		basePath    string
		shouldError bool
		expected    string
	}{
		{
			name:        "Valid path param",
			path:        "/users/alice",
			basePath:    "/users/",
			shouldError: false,
			expected:    "alice",
		},
		{
			name:        "Empty path param",
			path:        "/users/",
			basePath:    "/users/",
			shouldError: true,
		},
		{
			name:        "Just base path",
			path:        "/users",
			basePath:    "/users",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			rr := httptest.NewRecorder()

			param, err := ExtractPathParam(rr, req, tt.basePath)

			if tt.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.shouldError && param != tt.expected {
				t.Errorf("Expected param %q, got %q", tt.expected, param)
			}
		})
	}
}