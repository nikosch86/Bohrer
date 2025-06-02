package common

import (
	"fmt"
)

// URLBuilder provides utilities for building URLs with proper port handling
type URLBuilder struct {
	Domain string
}

// NewURLBuilder creates a new URL builder with the given domain
func NewURLBuilder(domain string) *URLBuilder {
	return &URLBuilder{Domain: domain}
}

// BuildHTTPURL builds an HTTP URL with optional port
func (b *URLBuilder) BuildHTTPURL(subdomain string, port int) string {
	if port == 80 || port == 0 {
		return fmt.Sprintf("http://%s.%s", subdomain, b.Domain)
	}
	return fmt.Sprintf("http://%s.%s:%d", subdomain, b.Domain, port)
}

// BuildHTTPSURL builds an HTTPS URL with optional port
func (b *URLBuilder) BuildHTTPSURL(subdomain string, port int) string {
	if port == 443 || port == 0 {
		return fmt.Sprintf("https://%s.%s", subdomain, b.Domain)
	}
	return fmt.Sprintf("https://%s.%s:%d", subdomain, b.Domain, port)
}

// BuildURLs builds both HTTP and HTTPS URLs for a subdomain
func (b *URLBuilder) BuildURLs(subdomain string, httpPort, httpsPort int) (httpURL, httpsURL string) {
	httpURL = b.BuildHTTPURL(subdomain, httpPort)
	httpsURL = b.BuildHTTPSURL(subdomain, httpsPort)
	return
}

// FormatTunnelSuccessMessage formats a success message for tunnel creation
func FormatTunnelSuccessMessage(httpURL, httpsURL string) string {
	return fmt.Sprintf("\r\n🎉 Tunnel Created Successfully!\r\n🌐 HTTP URL:  %s\r\n🔒 HTTPS URL: %s\r\n\r\n💡 Your local service is now publicly accessible!\r\n   Share these URLs with anyone who needs access.\r\n\r\n", httpURL, httpsURL)
}