#!/bin/bash

set -e

echo "🚀 Starting E2E test with tunnel URL capture"

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up..."
    docker compose -f docker-compose.e2e.yml down -v
}
trap cleanup EXIT

# Start services in background
echo "🔧 Starting services..."
docker compose -f docker-compose.e2e.yml up --build -d --remove-orphans

# Wait for services to be healthy using Docker health checks
echo "⏳ Waiting for services to be ready..."
timeout 30s bash -c "
    while true; do
        # Check if containers are running and healthy
        SSH_HEALTH=\$(docker compose -f docker-compose.e2e.yml ps ssh-server --format \"table {{.Health}}\" | tail -1)
        E2E_HEALTH=\$(docker compose -f docker-compose.e2e.yml ps e2e-client --format \"table {{.Health}}\" | tail -1)

        if [ \"\$SSH_HEALTH\" = \"healthy\" ] && [ \"\$E2E_HEALTH\" = \"healthy\" ]; then
            break
        fi
        sleep 1
    done
" || {
    echo "❌ Services failed to become healthy"
    exit 1
}

echo "✅ Services are ready"

# Start tunnel creation by running the dedicated tunnel HTTP test in background
echo "🔗 Starting tunnel HTTP test..."
docker compose -f docker-compose.e2e.yml exec -d e2e-client ./tunnel-http-test.sh

# Give some time for tunnel to be created
sleep 8

# Capture tunnel URL from server logs
echo "📋 Capturing tunnel URL from server logs..."
TUNNEL_URL=$(docker compose -f docker-compose.e2e.yml logs ssh-server | grep "🌐 HTTP:" | tail -1 | sed 's/.*🌐 HTTP: *//' | tr -d '\r\n ')

if [ -n "$TUNNEL_URL" ]; then
    echo "✅ Tunnel URL captured: $TUNNEL_URL"

    # Extract subdomain for testing
    SUBDOMAIN=$(echo "$TUNNEL_URL" | sed 's|http://||' | sed 's/\..*$//')
    echo "📝 Extracted subdomain: $SUBDOMAIN"

    # Test HTTP request through tunnel from within Docker network
    echo "🌐 Testing HTTP request through tunnel..."
    RESPONSE=$(docker compose -f docker-compose.e2e.yml exec -T e2e-client curl -s -w "\n%{http_code}" -H "Host: $SUBDOMAIN.ssh-server" "http://ssh-server/" 2>&1 || echo -e "FAILED\n000")
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)

    echo "📊 HTTP Response:"
    echo "  Status Code: $HTTP_CODE"
    echo "  Body: $BODY"

    # Validate response
    if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q "Hello from sample HTTP server"; then
        echo ""
        echo "🎉 ████████████████████████████████████████"
        echo "🎉 ██  COMPLETE E2E SUCCESS!        ██"
        echo "🎉 ████████████████████████████████████████"
        echo ""
        echo "✅ VALIDATED:"
        echo "   🔗 SSH tunnel creation"
        echo "   📡 Tunnel URL capture from logs"
        echo "   🌐 HTTP request through tunnel"
        echo "   📤 Real data from sample server"
        echo ""
        echo "🏆 True end-to-end validation complete!"
    else
        echo "❌ HTTP request through tunnel failed"
        echo "Expected: 200 with 'Hello from sample HTTP server'"
        echo "Got: $HTTP_CODE with '$BODY'"
        exit 1
    fi
else
    echo "❌ Could not capture tunnel URL from server logs"
    echo "Server logs:"
    docker compose -f docker-compose.e2e.yml logs ssh-server | tail -20
    exit 1
fi

echo ""
echo "🎯 E2E test with URL capture completed successfully!"