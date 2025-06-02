package acme

import (
	"fmt"
	"sync"
	"time"
)

// ACMERateLimiter implements rate limiting for Let's Encrypt production API
// Based on official Let's Encrypt rate limits: https://letsencrypt.org/docs/rate-limits/
type ACMERateLimiter struct {
	mu sync.RWMutex

	// Authorization failure tracking (5 failures per hostname per account per hour)
	authFailures map[string][]time.Time

	// New order tracking (300 new orders per account every 3 hours)
	newOrders []time.Time

	// Certificate tracking per domain (50 certificates per registered domain every 7 days)
	domainCerts map[string][]time.Time

	// Whether this is production (staging has no limits)
	isProduction bool
}

// NewACMERateLimiter creates a new rate limiter
func NewACMERateLimiter(isProduction bool) *ACMERateLimiter {
	return &ACMERateLimiter{
		authFailures: make(map[string][]time.Time),
		newOrders:    make([]time.Time, 0),
		domainCerts:  make(map[string][]time.Time),
		isProduction: isProduction,
	}
}

// CanMakeNewOrder checks if we can make a new certificate order
// Limit: 300 new orders per account every 3 hours
func (rl *ACMERateLimiter) CanMakeNewOrder() error {
	if !rl.isProduction {
		return nil // No limits for staging
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	threeHoursAgo := now.Add(-3 * time.Hour)

	// Remove old entries
	validOrders := make([]time.Time, 0)
	for _, orderTime := range rl.newOrders {
		if orderTime.After(threeHoursAgo) {
			validOrders = append(validOrders, orderTime)
		}
	}
	rl.newOrders = validOrders

	// Check limit
	if len(rl.newOrders) >= 300 {
		return fmt.Errorf("rate limit exceeded: 300 new orders per 3 hours (current: %d)", len(rl.newOrders))
	}

	return nil
}

// RecordNewOrder records that we made a new certificate order
func (rl *ACMERateLimiter) RecordNewOrder() {
	if !rl.isProduction {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.newOrders = append(rl.newOrders, time.Now())
}

// CanRetryAuthFailure checks if we can retry authorization for a hostname
// Limit: 5 authorization failures per hostname per account per hour
func (rl *ACMERateLimiter) CanRetryAuthFailure(hostname string) error {
	if !rl.isProduction {
		return nil // No limits for staging
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	oneHourAgo := now.Add(-1 * time.Hour)

	// Remove old failures for this hostname
	failures := rl.authFailures[hostname]
	validFailures := make([]time.Time, 0)
	for _, failureTime := range failures {
		if failureTime.After(oneHourAgo) {
			validFailures = append(validFailures, failureTime)
		}
	}
	rl.authFailures[hostname] = validFailures

	// Check limit
	if len(validFailures) >= 5 {
		return fmt.Errorf("rate limit exceeded: 5 authorization failures per hostname per hour for %s (current: %d)", hostname, len(validFailures))
	}

	return nil
}

// RecordAuthFailure records an authorization failure for a hostname
func (rl *ACMERateLimiter) RecordAuthFailure(hostname string) {
	if !rl.isProduction {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.authFailures[hostname] == nil {
		rl.authFailures[hostname] = make([]time.Time, 0)
	}
	rl.authFailures[hostname] = append(rl.authFailures[hostname], time.Now())
}

// CanIssueCertificateForDomain checks if we can issue a certificate for a domain
// Limit: 50 certificates per registered domain every 7 days
func (rl *ACMERateLimiter) CanIssueCertificateForDomain(domain string) error {
	if !rl.isProduction {
		return nil // No limits for staging
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)

	// Remove old certificates for this domain
	certs := rl.domainCerts[domain]
	validCerts := make([]time.Time, 0)
	for _, certTime := range certs {
		if certTime.After(sevenDaysAgo) {
			validCerts = append(validCerts, certTime)
		}
	}
	rl.domainCerts[domain] = validCerts

	// Check limit
	if len(validCerts) >= 50 {
		return fmt.Errorf("rate limit exceeded: 50 certificates per domain per 7 days for %s (current: %d)", domain, len(validCerts))
	}

	return nil
}

// RecordCertificateIssued records that we issued a certificate for a domain
func (rl *ACMERateLimiter) RecordCertificateIssued(domain string) {
	if !rl.isProduction {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.domainCerts[domain] == nil {
		rl.domainCerts[domain] = make([]time.Time, 0)
	}
	rl.domainCerts[domain] = append(rl.domainCerts[domain], time.Now())
}

// GetRateLimitStatus returns current rate limit status for monitoring
func (rl *ACMERateLimiter) GetRateLimitStatus() map[string]interface{} {
	if !rl.isProduction {
		return map[string]interface{}{
			"environment": "staging",
			"limits":      "none",
		}
	}

	rl.mu.RLock()
	defer rl.mu.RUnlock()

	now := time.Now()

	// Count recent orders (3 hours)
	threeHoursAgo := now.Add(-3 * time.Hour)
	recentOrders := 0
	for _, orderTime := range rl.newOrders {
		if orderTime.After(threeHoursAgo) {
			recentOrders++
		}
	}

	// Count recent failures (1 hour)
	oneHourAgo := now.Add(-1 * time.Hour)
	recentFailures := make(map[string]int)
	for hostname, failures := range rl.authFailures {
		count := 0
		for _, failureTime := range failures {
			if failureTime.After(oneHourAgo) {
				count++
			}
		}
		if count > 0 {
			recentFailures[hostname] = count
		}
	}

	// Count recent certificates (7 days)
	sevenDaysAgo := now.Add(-7 * 24 * time.Hour)
	recentCerts := make(map[string]int)
	for domain, certs := range rl.domainCerts {
		count := 0
		for _, certTime := range certs {
			if certTime.After(sevenDaysAgo) {
				count++
			}
		}
		if count > 0 {
			recentCerts[domain] = count
		}
	}

	return map[string]interface{}{
		"environment": "production",
		"new_orders": map[string]interface{}{
			"current": recentOrders,
			"limit":   300,
			"window":  "3 hours",
		},
		"auth_failures":       recentFailures,
		"domain_certificates": recentCerts,
	}
}
