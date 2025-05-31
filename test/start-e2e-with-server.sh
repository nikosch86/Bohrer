#!/bin/bash

set -e

echo "🚀 Starting combined E2E test with embedded sample server"

# Start the sample HTTP server in the background
echo "🌐 Starting sample HTTP server on localhost:3000..."
PORT=3000 ./sample-server &
SERVER_PID=$!

# Wait for the sample server to be ready
echo "⏳ Waiting for sample server to be ready..."
timeout 30s bash -c "
    while true; do
        if curl -f http://localhost:3000/health >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
" || {
    echo "❌ Sample server failed to start"
    exit 1
}

echo "✅ Sample server is ready"

# Function to cleanup on exit
cleanup() {
    echo "🧹 Cleaning up sample server..."
    kill $SERVER_PID 2>/dev/null || true
}
trap cleanup EXIT

# Run the e2e tests
echo "🧪 Running E2E tests..."
./e2e-test.sh

echo "🎉 Combined E2E test completed successfully!"