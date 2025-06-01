#!/bin/bash

set -e

echo "🔑 Generating SSH keys for testing..."

# Create test directory if it doesn't exist
TEST_DIR="$(dirname "$0")"
mkdir -p "$TEST_DIR"

# Generate SSH key pair for testing
ssh-keygen -t rsa -b 2048 -f "$TEST_DIR/ssh_key" -N "" -C "e2e-test-key" >/dev/null 2>&1

# Create authorized_keys file with the public key
cp "$TEST_DIR/ssh_key.pub" "$TEST_DIR/test_authorized_keys"

# echo "✅ Generated SSH keys:"
# echo "  Private key: $TEST_DIR/ssh_key"
# echo "  Public key: $TEST_DIR/ssh_key.pub"
# echo "  Authorized keys: $TEST_DIR/test_authorized_keys"

# Set proper permissions
chmod 600 "$TEST_DIR/ssh_key"
chmod 644 "$TEST_DIR/ssh_key.pub"
chmod 644 "$TEST_DIR/test_authorized_keys"

echo "✅ SSH keys ready for testing"