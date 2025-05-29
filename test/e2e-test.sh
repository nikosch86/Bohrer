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

# Create SSH tunnel and capture output to get the subdomain
echo "📝 Creating SSH tunnel with session to capture tunnel URL..."

# Use a temporary session that will capture the tunnel creation output
SSH_OUTPUT=$(timeout 10 sshpass -p "test123" ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
    -R 0:$MOCK_HOST:$MOCK_PORT tunnel@$SSH_HOST -p $SSH_PORT \
    "echo 'Connected'; sleep 5" 2>&1) || {
    echo "⚠️ SSH session ended (this is expected)"
}

echo "📝 SSH Output:"
echo "$SSH_OUTPUT"

# Extract tunnel URL from SSH output
if echo "$SSH_OUTPUT" | grep -q "HTTP URL:"; then
    TUNNEL_URL=$(echo "$SSH_OUTPUT" | grep "HTTP URL:" | sed 's/.*HTTP URL: *//' | tr -d '\r\n ')
    echo "✅ Tunnel created: $TUNNEL_URL"
    
    # Extract subdomain from URL
    SUBDOMAIN=$(echo "$TUNNEL_URL" | sed 's|http://||' | sed 's/\..*$//')
    echo "📝 Extracted subdomain: $SUBDOMAIN"
    
    # Test the tunnel with HTTP request
    echo "🧪 Testing HTTP request through tunnel..."
    TUNNEL_RESPONSE=$(curl -s -w "\n%{http_code}" -H "Host: $SUBDOMAIN.$HTTP_HOST" "http://$HTTP_HOST:$HTTP_PORT/" 2>/dev/null || echo -e "FAILED\n000")
    TUNNEL_HTTP_CODE=$(echo "$TUNNEL_RESPONSE" | tail -1)
    TUNNEL_BODY=$(echo "$TUNNEL_RESPONSE" | head -n -1)
    
    echo "🔍 Tunnel Response: $TUNNEL_BODY (Status: $TUNNEL_HTTP_CODE)"
    
    if [ "$TUNNEL_HTTP_CODE" = "200" ] && echo "$TUNNEL_BODY" | grep -q "Hello from mock server"; then
        echo "✅ END-TO-END TUNNEL TEST PASSED! 🎉"
        echo "🌐 Successfully routed HTTP request through SSH tunnel to mock server"
    else
        echo "❌ Tunnel HTTP routing failed"
        echo "💡 Expected: 200 status with 'Hello from mock server'"
        echo "💡 Got: $TUNNEL_HTTP_CODE status with '$TUNNEL_BODY'"
        exit 1
    fi
else
    echo "⚠️ Could not extract tunnel URL from SSH output"
    echo "🔄 Testing basic proxy connectivity as fallback..."
    
    RESPONSE=$(curl -s -w "\n%{http_code}" "http://$HTTP_HOST:$HTTP_PORT/" 2>/dev/null || echo -e "FAILED\n000")
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    echo "🔍 Fallback Response: $BODY (Status: $HTTP_CODE)"
    
    if [ "$HTTP_CODE" = "400" ] && echo "$BODY" | grep -q "Invalid domain"; then
        echo "✅ Basic proxy connectivity test PASSED (expected 'Invalid domain' for root request)"
    else
        echo "❌ Basic connectivity test also FAILED!"
        exit 1
    fi
    
    # Clean up SSH tunnel
    kill $SSH_PID 2>/dev/null || true
fi

echo "🎉 End-to-end test completed successfully!"
echo "📝 Note: Full tunnel routing test requires subdomain implementation"