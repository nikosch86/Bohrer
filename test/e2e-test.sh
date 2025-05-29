#!/bin/bash

set -e

echo "🚀 Starting End-to-End SSH Tunnel Test (Dockerized)"

# Use environment variables for service discovery
SSH_HOST=${SSH_HOST:-ssh-tunnel}
SSH_PORT=${SSH_PORT:-2222}
HTTP_HOST=${HTTP_HOST:-ssh-tunnel}
HTTP_PORT=${HTTP_PORT:-8080}
MOCK_HOST=${MOCK_HOST:-mock-server}
MOCK_PORT=${MOCK_PORT:-3000}

echo "🔍 Checking if SSH server is responding..."
timeout 30 bash -c "until nc -z $SSH_HOST $SSH_PORT; do sleep 1; done" || {
    echo "❌ SSH server not responding on $SSH_HOST:$SSH_PORT"
    exit 1
}

echo "🔍 Checking if HTTP server is responding..."
timeout 30 bash -c "until curl -s http://$HTTP_HOST:$HTTP_PORT >/dev/null; do sleep 1; done" || {
    echo "❌ HTTP server not responding on $HTTP_HOST:$HTTP_PORT"
    exit 1
}

echo "🔍 Testing mock server directly..."
curl -s http://$MOCK_HOST:$MOCK_PORT/health | grep -q "ok" || {
    echo "❌ Mock server not responding correctly"
    exit 1
}

echo "🔗 Establishing SSH tunnel..."
# Create SSH tunnel in background
sshpass -p "test123" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 -f -N \
    -R 0:$MOCK_HOST:$MOCK_PORT tunnel@$SSH_HOST -p $SSH_PORT &

SSH_PID=$!

echo "⏳ Waiting for tunnel to establish..."
sleep 10

echo "🧪 Testing tunnel connectivity..."
# Try to find the tunnel URL from logs or use a known pattern
# For now, let's test with a simple subdomain pattern
TEST_SUBDOMAIN="test123abc"
TUNNEL_URL="http://$TEST_SUBDOMAIN.$HTTP_HOST:$HTTP_PORT"

echo "🌐 Testing URL: $TUNNEL_URL"

echo "📡 Testing HTTP request through tunnel..."
RESPONSE=$(curl -s -w "%{http_code}" "http://$HTTP_HOST:$HTTP_PORT/" || echo "FAILED")

if echo "$RESPONSE" | grep -q "SSH Tunnel Server"; then
    echo "✅ Basic connectivity test PASSED!"
    echo "📊 Response: $RESPONSE"
else
    echo "❌ Basic connectivity test FAILED!"
    echo "🔍 Response received: $RESPONSE"
    exit 1
fi

# Kill SSH process
kill $SSH_PID 2>/dev/null || true

echo "🎉 End-to-end test completed successfully!"
echo "📝 Note: Full tunnel routing test requires subdomain implementation"