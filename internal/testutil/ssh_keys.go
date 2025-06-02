package testutil

// Valid test SSH keys for use across test files
const (
	// ValidRSAKey is a valid RSA SSH public key for testing
	ValidRSAKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQJlMbPPckn2OGPx+z7rkrQF1nHB1BfmmHecBCYr7sL6ozZPZZnRrCNvyu5CL1JmE6Hm4t9K3hGauvgDw0hOzwz5/5OCD6R8ttKoAhekSs2kaLN3Q8pAIWknKKE6dlCJcqJo8mdOcgYUf4SQ3tafGmHXzvWMfWsMKdhH8A6R+RaYOn6KaxU7F9bPKg8QpNhKDQcw5ZgcKkjL9dYoTosXMxJ9ks9zPD3P2LLvV8rV3CdRnO0w3sboaVGmMEYPCU0Rzl1CVFLb/cOJmPNxK1xXfrDKTGDpIMAcr+xNnJwe7ClbADJxVtcBYrKKg3i1s5LZ7RE3pfmLfAOIhXMXJyVXsn test@example.com"
	
	// ValidED25519Key is a valid ED25519 SSH public key for testing
	ValidED25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"
	
	// InvalidKey is an invalid SSH key for testing error cases
	InvalidKey = "not-a-valid-ssh-key"
)