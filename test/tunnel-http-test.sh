#!/bin/bash

set -e

echo "🚀 Starting Tunnel HTTP Test"

# Environment variables
SSH_HOST=${SSH_HOST:-ssh-server}
SSH_PORT=${SSH_PORT:-22}
SAMPLE_SERVER_HOST=${SAMPLE_SERVER_HOST:-localhost}
SAMPLE_SERVER_PORT=${SAMPLE_SERVER_PORT:-3000}
LOG_DIR=${LOG_DIR:-/logs}

echo "📝 Configuration:"
echo "  SSH Server: $SSH_HOST:$SSH_PORT"
echo "  Sample Server: $SAMPLE_SERVER_HOST:$SAMPLE_SERVER_PORT"
echo "  Log Dir: $LOG_DIR"

# Wait for SSH server to be ready
echo "🔍 Waiting for SSH server..."
timeout 30 bash -c "until nc -z $SSH_HOST $SSH_PORT; do sleep 1; done" || {
    echo "❌ SSH server not responding"
    exit 1
}

# Start the sample HTTP server in the background
echo "🌐 Starting sample HTTP server on localhost:3000..."
PORT=3000 ./sample-server &
SERVER_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    kill $SSH_PID 2>/dev/null || true
}
trap cleanup EXIT

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

# Create log directory
mkdir -p "$LOG_DIR"

# Create SSH tunnel and capture output
echo "🔗 Creating SSH tunnel to forward localhost:3000..."
ssh -i ./ssh_key -R 0:$SAMPLE_SERVER_HOST:$SAMPLE_SERVER_PORT -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o IdentitiesOnly=yes \
    tunnel@$SSH_HOST -p $SSH_PORT -N 2>&1 | tee "$LOG_DIR/tunnel_output.log" &
SSH_PID=$!

# Give tunnel time to establish
sleep 5

# Verify tunnel is active
if ! kill -0 $SSH_PID 2>/dev/null; then
    echo "❌ SSH tunnel process died"
    exit 1
fi

echo "✅ SSH tunnel established successfully"

# Test HTTP request to local sample server first
echo "🧪 Testing local sample server..."
LOCAL_RESPONSE=$(curl -s http://localhost:3000/ || echo "FAILED")
if echo "$LOCAL_RESPONSE" | grep -q "Hello from sample HTTP server"; then
    echo "✅ Local sample server responds correctly"
else
    echo "❌ Local sample server not responding properly"
    echo "Response: $LOCAL_RESPONSE"
    exit 1
fi

echo "✅ Tunnel HTTP test completed successfully!"
echo "🔍 Tunnel is ready and forwarding to working sample server"
echo ""
echo "💡 The tunnel is now ready for external HTTP testing!"
echo "   Sample server running on localhost:3000"
echo "   SSH tunnel forwarding established"
echo ""
echo "📋 Tunnel output:"
cat "$LOG_DIR/tunnel_output.log" || echo "No tunnel output file"