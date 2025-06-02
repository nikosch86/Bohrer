package acme

import (
	"strings"
	"testing"
	"time"
)

func TestNewACMERateLimiter(t *testing.T) {
	// Test staging rate limiter
	stagingLimiter := NewACMERateLimiter(false)
	if stagingLimiter.isProduction {
		t.Error("Expected staging limiter to have isProduction=false")
	}

	// Test production rate limiter
	prodLimiter := NewACMERateLimiter(true)
	if !prodLimiter.isProduction {
		t.Error("Expected production limiter to have isProduction=true")
	}
}

func TestNewOrderRateLimit(t *testing.T) {
	// Test staging (no limits)
	stagingLimiter := NewACMERateLimiter(false)
	for i := 0; i < 400; i++ {
		if err := stagingLimiter.CanMakeNewOrder(); err != nil {
			t.Errorf("Staging should have no limits, got error: %v", err)
		}
		stagingLimiter.RecordNewOrder()
	}

	// Test production limits
	prodLimiter := NewACMERateLimiter(true)

	// Should allow up to 300 orders
	for i := 0; i < 300; i++ {
		if err := prodLimiter.CanMakeNewOrder(); err != nil {
			t.Errorf("Should allow order %d, got error: %v", i+1, err)
		}
		prodLimiter.RecordNewOrder()
	}

	// 301st order should be rejected
	if err := prodLimiter.CanMakeNewOrder(); err == nil {
		t.Error("Expected 301st order to be rejected")
	}
}

func TestAuthFailureRateLimit(t *testing.T) {
	hostname := "test.example.com"

	// Test staging (no limits)
	stagingLimiter := NewACMERateLimiter(false)
	for i := 0; i < 10; i++ {
		if err := stagingLimiter.CanRetryAuthFailure(hostname); err != nil {
			t.Errorf("Staging should have no limits, got error: %v", err)
		}
		stagingLimiter.RecordAuthFailure(hostname)
	}

	// Test production limits
	prodLimiter := NewACMERateLimiter(true)

	// Should allow up to 5 failures per hour
	for i := 0; i < 5; i++ {
		if err := prodLimiter.CanRetryAuthFailure(hostname); err != nil {
			t.Errorf("Should allow failure %d, got error: %v", i+1, err)
		}
		prodLimiter.RecordAuthFailure(hostname)
	}

	// 6th failure should be rejected
	if err := prodLimiter.CanRetryAuthFailure(hostname); err == nil {
		t.Error("Expected 6th auth failure to be rejected")
	}

	// Different hostname should still work
	if err := prodLimiter.CanRetryAuthFailure("other.example.com"); err != nil {
		t.Errorf("Different hostname should be allowed, got error: %v", err)
	}
}

func TestDomainCertificateRateLimit(t *testing.T) {
	domain := "example.com"

	// Test staging (no limits)
	stagingLimiter := NewACMERateLimiter(false)
	for i := 0; i < 60; i++ {
		if err := stagingLimiter.CanIssueCertificateForDomain(domain); err != nil {
			t.Errorf("Staging should have no limits, got error: %v", err)
		}
		stagingLimiter.RecordCertificateIssued(domain)
	}

	// Test production limits
	prodLimiter := NewACMERateLimiter(true)

	// Should allow up to 50 certificates per week
	for i := 0; i < 50; i++ {
		if err := prodLimiter.CanIssueCertificateForDomain(domain); err != nil {
			t.Errorf("Should allow certificate %d, got error: %v", i+1, err)
		}
		prodLimiter.RecordCertificateIssued(domain)
	}

	// 51st certificate should be rejected
	if err := prodLimiter.CanIssueCertificateForDomain(domain); err == nil {
		t.Error("Expected 51st certificate to be rejected")
	}

	// Different domain should still work
	if err := prodLimiter.CanIssueCertificateForDomain("other.example.com"); err != nil {
		t.Errorf("Different domain should be allowed, got error: %v", err)
	}
}

func TestRateLimitTimeWindows(t *testing.T) {
	prodLimiter := NewACMERateLimiter(true)
	hostname := "test.example.com"

	// Fill up auth failures
	for i := 0; i < 5; i++ {
		prodLimiter.RecordAuthFailure(hostname)
	}

	// Should be rate limited
	if err := prodLimiter.CanRetryAuthFailure(hostname); err == nil {
		t.Error("Expected to be rate limited")
	}

	// Simulate time passing by manually adjusting timestamps
	prodLimiter.mu.Lock()
	oldTime := time.Now().Add(-2 * time.Hour) // Make failures older than 1 hour
	for i := range prodLimiter.authFailures[hostname] {
		prodLimiter.authFailures[hostname][i] = oldTime
	}
	prodLimiter.mu.Unlock()

	// Should now be allowed again
	if err := prodLimiter.CanRetryAuthFailure(hostname); err != nil {
		t.Errorf("Should be allowed after time window, got error: %v", err)
	}
}

func TestGetRateLimitStatus(t *testing.T) {
	// Test staging status
	stagingLimiter := NewACMERateLimiter(false)
	status := stagingLimiter.GetRateLimitStatus()
	if status["environment"] != "staging" {
		t.Error("Expected staging environment in status")
	}

	// Test production status
	prodLimiter := NewACMERateLimiter(true)

	// Add some activity
	prodLimiter.RecordNewOrder()
	prodLimiter.RecordAuthFailure("test.example.com")
	prodLimiter.RecordCertificateIssued("example.com")

	status = prodLimiter.GetRateLimitStatus()
	if status["environment"] != "production" {
		t.Error("Expected production environment in status")
	}

	// Check that new orders are tracked
	newOrders, ok := status["new_orders"].(map[string]interface{})
	if !ok {
		t.Error("Expected new_orders in status")
	}
	if newOrders["current"] != 1 {
		t.Errorf("Expected 1 new order, got %v", newOrders["current"])
	}
	if newOrders["limit"] != 300 {
		t.Errorf("Expected limit of 300, got %v", newOrders["limit"])
	}
}

func TestRateLimitErrorMessages(t *testing.T) {
	prodLimiter := NewACMERateLimiter(true)

	// Fill up new orders
	for i := 0; i < 300; i++ {
		prodLimiter.RecordNewOrder()
	}

	err := prodLimiter.CanMakeNewOrder()
	if err == nil {
		t.Error("Expected rate limit error")
	}

	if !strings.Contains(err.Error(), "300 new orders per 3 hours") {
		t.Errorf("Expected specific error message, got: %v", err)
	}

	// Test auth failure error
	hostname := "test.example.com"
	for i := 0; i < 5; i++ {
		prodLimiter.RecordAuthFailure(hostname)
	}

	err = prodLimiter.CanRetryAuthFailure(hostname)
	if err == nil {
		t.Error("Expected auth failure rate limit error")
	}

	if !strings.Contains(err.Error(), "5 authorization failures per hostname per hour") {
		t.Errorf("Expected specific error message, got: %v", err)
	}

	// Test domain certificate error
	domain := "example.com"
	for i := 0; i < 50; i++ {
		prodLimiter.RecordCertificateIssued(domain)
	}

	err = prodLimiter.CanIssueCertificateForDomain(domain)
	if err == nil {
		t.Error("Expected domain certificate rate limit error")
	}

	if !strings.Contains(err.Error(), "50 certificates per domain per 7 days") {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}
