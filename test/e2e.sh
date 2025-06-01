#!/bin/bash -fu
# shellcheck disable=SC2317

# Configuration
COMPOSE_FILE="docker-compose.e2e.yml"
LOG_DIR="test/logs"

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up..."
    docker compose -f "$COMPOSE_FILE" down -v
    rm -rf "$LOG_DIR"
    # Clean up generated SSH keys
    rm -f test/ssh_key test/ssh_key.pub test/test_authorized_keys
}
trap cleanup EXIT

mkdir -p "$LOG_DIR"

# Generate SSH keys for testing
echo "🔑 Setting up SSH keys for testing..."
if [ ! -f "test/ssh_key" ]; then
    ./test/generate-ssh-keys.sh
else
    echo "✅ SSH keys already exist"
fi

# Test Results Tracking
TESTS_PASSED=0
TESTS_FAILED=0
FAILED_TESTS=()

# Function to run a test and track results
run_test() {
    local test_name="$1"
    local test_function="$2"

    echo ""
    echo "🧪 ============================================"
    echo "🧪 Running: $test_name"

    if $test_function; then
        echo "✅ PASSED: $test_name"
        ((TESTS_PASSED++)) || true
    else
        echo "❌ FAILED: $test_name"
        ((TESTS_FAILED++)) || true
        FAILED_TESTS+=("$test_name")
    fi
    echo "🧪 ============================================"
}

# Utility function to execute commands in containers
exec_in_container() {
    local service="$1"
    shift
    docker compose -f "$COMPOSE_FILE" exec -T "$service" "$@" >> "${LOG_DIR}/$service.log" 2>&1
}

# Main execution
echo "Building services"
docker compose -f "$COMPOSE_FILE" build > /dev/null
echo "🔧 Starting services..."
docker compose -f "$COMPOSE_FILE" up -d --remove-orphans --wait --wait-timeout 15 || {
    echo "❌ Services failed to become healthy"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
}

test_mock_server() {
    # Test mock server response from http-client
    local service="http-client"
    if ! exec_in_container $service curl -sf "http://mock-server:3000/health" >/dev/null 2>&1; then
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_ssh_connection() {
    # Test SSH server accepts connections by attempting a quick tunnel
    # If this succeeds, we know SSH auth and connection works
    local service="ssh-client"
    if ! exec_in_container $service timeout 1s ssh -i ./ssh_key -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o IdentitiesOnly=yes \
        -R 0:localhost:9999 tunnel@ssh-server -p 22 -N; then
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_ssh_tunnel_url_parsing() {
    local service="ssh-client"
    > "${LOG_DIR}/$service.log"

    # Start SSH tunnel in background and capture output
    echo "🚀 Creating SSH tunnel..."
    exec_in_container $service bash -c "
        ssh -i ./ssh_key -R 0:mock-server:3000 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o IdentitiesOnly=yes \
            tunnel@ssh-server -p 22 2>&1 | tee /logs/tunnel.log &
        echo \$! > /logs/ssh_pid
    " &

    # Wait for tunnel to establish
    sleep 2

    # Check if SSH process is still running
    exec_in_container $service cat /logs/ssh_pid 2>/dev/null
    SSH_PID=$(tail -n1 "${LOG_DIR}/$service.log")
    if [ -n "$SSH_PID" ] && exec_in_container $service kill -0 "$SSH_PID" 2>/dev/null; then
        echo "✅ SSH tunnel process running with PID $SSH_PID"

        # Try to extract tunnel URL from logs
        exec_in_container $service grep -o 'https://[^[:space:]]*' /logs/tunnel.log 2>/dev/null
        TUNNEL_URL=$(tail -n1 "${LOG_DIR}/$service.log")

        if [ -n "$TUNNEL_URL" ]; then
            echo "✅ Tunnel URL captured: $TUNNEL_URL"
            # Save URL for HTTP test
            echo "$TUNNEL_URL" > "$LOG_DIR/tunnel_url.txt"
        else
            echo "⚠️  Tunnel established but URL not captured"
            cat "${LOG_DIR}/$service.log"
            return 1
        fi

        # Cleanup tunnel
        echo "🚀 Cleaning up SSH tunnel..."
        exec_in_container $service kill "$SSH_PID" 2>/dev/null
        return 0
    else
        echo "❌ SSH tunnel failed to establish"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_http_tunneling() {
    local service="ssh-client"
    > "${LOG_DIR}/$service.log"

    # Start SSH tunnel in background and capture output
    echo "🚀 Creating SSH tunnel..."
    exec_in_container $service bash -c "
        # Create named pipe for logging
        mkfifo /logs/ssh_pipe

        # Start tee in background to read from pipe
        tee /logs/tunnel.log < /logs/ssh_pipe &

        # Start SSH with output redirected to pipe
        ssh -i ./ssh_key -R 0:mock-server:3000 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o IdentitiesOnly=yes \
            tunnel@ssh-server -p 22 -vN > /logs/ssh_pipe 2>&1 &

        # Capture SSH PID
        echo \$! > /logs/ssh_pid

        # Clean up pipe when done
        sleep 0.1
        rm -f /logs/ssh_pipe
    " &

    # Wait for tunnel to establish
    sleep 2

    # Check if SSH process is still running
    exec_in_container $service cat /logs/ssh_pid 2>/dev/null
    SSH_PID=$(tail -n1 "${LOG_DIR}/$service.log")
    if [ -z "$SSH_PID" ] || ! exec_in_container $service kill -0 "$SSH_PID" 2>/dev/null; then
        echo "❌ SSH tunnel failed to establish for HTTP test"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi

    # Try to extract tunnel URL from logs
    TUNNEL_URL=$(docker compose -f "$COMPOSE_FILE" logs -n2 ssh-server | grep -o 'https://[^[:space:]]*')

    if [ -n "$TUNNEL_URL" ]; then
        echo "✅ Tunnel URL captured: $TUNNEL_URL"
        # Save URL for HTTP test
        echo "$TUNNEL_URL" > "$LOG_DIR/tunnel_url.txt"
    else
        echo "⚠️  Tunnel established but URL not captured"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi

    # Extract the subdomain from the tunnel URL
    SUBDOMAIN=$(echo "$TUNNEL_URL" | sed 's|https://\([^.]*\)\..*|\1|')
    if [ -z "$SUBDOMAIN" ]; then
        echo "❌ Could not extract subdomain from tunnel URL"
        exec_in_container $service kill "$SSH_PID" 2>/dev/null || true
        return 1
    fi

    echo "✅ Extracted subdomain: $SUBDOMAIN"

    # Test HTTP tunneling by using Host header to ssh-server directly
    # This works around the lack of wildcard DNS in Docker
    echo "🌐 Testing HTTP request through tunnel..."

    # Clear previous http-client logs
    > "${LOG_DIR}/http-client.log"

    # Make the HTTP request and capture response
    if exec_in_container http-client curl -s "http://ssh-server/" \
        -H "Host: ${SUBDOMAIN}.ssh-server" \
        -w "HTTP Status: %{http_code}\n"; then

        # Get the response content
        RESPONSE_CONTENT=$(tail -n 10 "${LOG_DIR}/http-client.log" | head -n -1)
        HTTP_STATUS=$(tail -n 1 "${LOG_DIR}/http-client.log" | grep -o '[0-9]*')

        # Check if we got expected mock server response
        if [ "$HTTP_STATUS" = "200" ]; then
            # Check for expected JSON fields from sample HTTP server
            if echo "$RESPONSE_CONTENT" | grep -q "Hello from sample HTTP server" && \
               echo "$RESPONSE_CONTENT" | grep -q "e2e-test-server"; then
                echo "✅ HTTP tunneling test successful - received expected sample server response"
            else
                echo "⚠️  HTTP request successful but unexpected content"
                echo "Expected: JSON response with 'Hello from sample HTTP server' and 'e2e-test-server'"
                echo "Received: $RESPONSE_CONTENT"
                return 1
            fi
        else
            echo "❌ HTTP request failed with status: $HTTP_STATUS"
            echo "Response: $RESPONSE_CONTENT"
            return 1
        fi
    else
        echo "❌ HTTP request through tunnel failed"
        echo "❌ $service Logs:"
        cat "${LOG_DIR}/$service.log"
        echo -en "\n\n ❌ http-client Logs:\n"
        cat "${LOG_DIR}/http-client.log"
        return 1
    fi

    # Cleanup tunnel
    echo "🚀 Cleaning up SSH tunnel..."
    exec_in_container $service kill "$SSH_PID" 2>/dev/null || true
    return 0
}

test_webui_http_404() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Test that WebUI returns 404 on HTTP (non-HTTPS)
    exec_in_container $service curl -s -o /dev/null -w "%{http_code}" http://ssh-server/
    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "404" ]; then
        return 0
    else
        echo "❌ WebUI returned unexpected status on HTTP: $HTTP_STATUS (expected 404)"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_https_wrong_credentials() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Test with wrong credentials
    exec_in_container $service curl -k -s -o /dev/null -w "%{http_code}" -u wronguser:wrongpass https://ssh-server/
    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "401" ]; then
        return 0
    else
        echo "❌ WebUI returned unexpected status with wrong credentials: $HTTP_STATUS (expected 401)"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_https_no_credentials() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Test without credentials
    exec_in_container $service curl -k -s -o /dev/null -w "%{http_code}" https://ssh-server/
    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "401" ]; then
        return 0
    else
        echo "❌ WebUI returned unexpected status without credentials: $HTTP_STATUS (expected 401)"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_https_correct_credentials() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Get server logs and extract the WebUI credentials
    docker compose -f "$COMPOSE_FILE" logs ssh-server > "${LOG_DIR}/server-startup.log" 2>&1

    # Parse username and password from the logs
    WEBUI_USERNAME=$(grep -o "Username: [^ ]*" "${LOG_DIR}/server-startup.log" | tail -1 | cut -d' ' -f2)
    WEBUI_PASSWORD=$(grep -o "Password: [^ ]*" "${LOG_DIR}/server-startup.log" | tail -1 | cut -d' ' -f2)

    if [ -z "$WEBUI_USERNAME" ] || [ -z "$WEBUI_PASSWORD" ]; then
        echo "❌ Failed to parse WebUI credentials from server logs"
        echo "Server logs:"
        cat "${LOG_DIR}/server-startup.log"
        return 1
    fi

    # Test with correct credentials
    exec_in_container $service curl -k -s -o /dev/null -w "%{http_code}" -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" https://ssh-server/
    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "200" ]; then
        return 0
    else
        echo "❌ WebUI returned unexpected status with correct credentials: $HTTP_STATUS (expected 200)"
        echo "Using credentials: username=$WEBUI_USERNAME"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_tunnel_display() {
    local service="ssh-client"
    > "${LOG_DIR}/$service.log"

    # Start SSH tunnel in background
    exec_in_container $service bash -c "
        ssh -i ./ssh_key -R 0:mock-server:3000 -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o IdentitiesOnly=yes \
            tunnel@ssh-server -p 22 -vN &
        echo \$! > /logs/ssh_pid
    " &

    # Wait for tunnel to establish
    sleep 3

    # Check if SSH process is still running
    exec_in_container $service cat /logs/ssh_pid 2>/dev/null
    SSH_PID=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ -z "$SSH_PID" ] || ! exec_in_container $service kill -0 "$SSH_PID" 2>/dev/null; then
        echo "❌ SSH tunnel failed to establish for WebUI test"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi

    # Get WebUI credentials
    docker compose -f "$COMPOSE_FILE" logs ssh-server > "${LOG_DIR}/server-startup.log" 2>&1
    WEBUI_USERNAME=$(grep -o "Username: [^ ]*" "${LOG_DIR}/server-startup.log" | tail -1 | cut -d' ' -f2)
    WEBUI_PASSWORD=$(grep -o "Password: [^ ]*" "${LOG_DIR}/server-startup.log" | tail -1 | cut -d' ' -f2)

    # Clear http-client logs
    > "${LOG_DIR}/http-client.log"

    # Get WebUI dashboard and check for tunnel information
    exec_in_container http-client curl -k -s -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" https://ssh-server/
    DASHBOARD_CONTENT=$(cat "${LOG_DIR}/http-client.log")

    # Check if dashboard contains tunnel information
    # The WebUI shows the local port mapping (localhost:PORT), not the remote target
    if echo "$DASHBOARD_CONTENT" | grep -q "Active Tunnels" && \
       echo "$DASHBOARD_CONTENT" | grep -q "<td>localhost:[0-9]*</td>"; then
        TUNNEL_DISPLAYED=true
    else
        echo "❌ WebUI does not show active tunnel information"
        echo "Dashboard content:"
        echo "$DASHBOARD_CONTENT"
        TUNNEL_DISPLAYED=false
    fi

    # Cleanup tunnel
    exec_in_container $service kill "$SSH_PID" 2>/dev/null || true

    if [ "$TUNNEL_DISPLAYED" = true ]; then
        return 0
    else
        return 1
    fi
}

# Helper function to get WebUI credentials
get_webui_credentials() {
    docker compose -f "$COMPOSE_FILE" logs ssh-server > "${LOG_DIR}/server-startup.log" 2>&1
    WEBUI_USERNAME=$(grep -o "Username: [^ ]*" "${LOG_DIR}/server-startup.log" | tail -1 | cut -d' ' -f2)
    WEBUI_PASSWORD=$(grep -o "Password: [^ ]*" "${LOG_DIR}/server-startup.log" | tail -1 | cut -d' ' -f2)

    if [ -z "$WEBUI_USERNAME" ] || [ -z "$WEBUI_PASSWORD" ]; then
        echo "❌ Failed to parse WebUI credentials from server logs"
        return 1
    fi

    export WEBUI_USERNAME WEBUI_PASSWORD
    return 0
}

test_webui_user_creation() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Get WebUI credentials
    if ! get_webui_credentials; then
        return 1
    fi

    # Test user creation via WebUI
    exec_in_container $service curl -k -s -w "%{http_code}" \
        -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" \
        -X POST \
        -d "username=testuser&password=testpassword123" \
        https://ssh-server/users

    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "303" ]; then  # Redirect after successful creation
        return 0
    else
        echo "❌ User creation failed with status: $HTTP_STATUS (expected 303)"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_user_creation_duplicate() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Get WebUI credentials
    if ! get_webui_credentials; then
        return 1
    fi

    # Try to create the same user again (should fail with 409 Conflict)
    exec_in_container $service curl -k -s -w "%{http_code}" \
        -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" \
        -X POST \
        -d "username=testuser&password=differentpassword" \
        https://ssh-server/users

    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "409" ]; then  # Conflict - user already exists
        return 0
    else
        echo "❌ Duplicate user creation returned unexpected status: $HTTP_STATUS (expected 409)"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_user_list() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Get WebUI credentials
    if ! get_webui_credentials; then
        return 1
    fi

    # Get users page and check if our test user is listed
    exec_in_container $service curl -k -s -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" https://ssh-server/users
    USER_PAGE_CONTENT=$(cat "${LOG_DIR}/$service.log")

    # Check if the test user appears in the user list
    if echo "$USER_PAGE_CONTENT" | grep -q "testuser"; then
        return 0
    else
        echo "❌ Test user not found in WebUI user list"
        echo "User page content:"
        echo "$USER_PAGE_CONTENT"
        return 1
    fi
}

test_ssh_user_authentication() {
    local service="ssh-client"
    > "${LOG_DIR}/$service.log"

    # Try to connect with the test user credentials
    # Check if authentication works by looking for auth success in server logs
    exec_in_container $service timeout 5s sshpass -p 'testpassword123' ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        testuser@ssh-server -p 22 \
        "echo 'SSH connection successful'" 2>&1

    # Also check server logs for authentication success
    AUTH_SUCCESS=$(docker compose -f "$COMPOSE_FILE" logs ssh-server | grep "User testuser authenticated successfully" | tail -1)

    # Check if we got the success message or authentication was logged
    if grep -q "SSH connection successful" "${LOG_DIR}/$service.log" || [ -n "$AUTH_SUCCESS" ]; then
        return 0
    else
        echo "❌ SSH authentication failed with created user"
        echo "Server logs auth check: '$AUTH_SUCCESS'"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_ssh_user_tunnel_creation() {
    local service="ssh-client"
    > "${LOG_DIR}/$service.log"

    # Start SSH tunnel with the test user
    exec_in_container $service bash -c "
        sshpass -p 'testpassword123' ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=10 \
            -o PreferredAuthentications=password \
            -o PubkeyAuthentication=no \
            -R 0:mock-server:3000 \
            testuser@ssh-server -p 22 -vN &
        echo \$! > /logs/ssh_pid
    " &

    # Wait for tunnel to establish
    sleep 3

    # Check if SSH process is still running
    exec_in_container $service cat /logs/ssh_pid 2>/dev/null
    SSH_PID=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ -n "$SSH_PID" ] && exec_in_container $service kill -0 "$SSH_PID" 2>/dev/null; then
        echo "✅ Tunnel creation successful with created user"

        # Check if tunnel appears in WebUI
        sleep 1
        > "${LOG_DIR}/http-client.log"
        get_webui_credentials
        exec_in_container http-client curl -k -s -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" https://ssh-server/
        DASHBOARD_CONTENT=$(cat "${LOG_DIR}/http-client.log")

        if echo "$DASHBOARD_CONTENT" | grep -q "Active Tunnels" && \
           echo "$DASHBOARD_CONTENT" | grep -q "<td>localhost:[0-9]*</td>"; then
            echo "✅  Tunnel created and visible in WebUI dashboard"
        else
            echo "⚠️  Tunnel created but not visible in WebUI dashboard"
        fi

        # Cleanup tunnel
        exec_in_container $service kill "$SSH_PID" 2>/dev/null || true
        return 0
    else
        echo "❌ Tunnel creation failed with created user"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_webui_user_deletion() {
    local service="http-client"
    > "${LOG_DIR}/$service.log"

    # Get WebUI credentials
    if ! get_webui_credentials; then
        return 1
    fi

    exec_in_container $service curl -k -s -w "%{http_code}" \
        -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" \
        -X DELETE \
        https://ssh-server/users/testuser

    HTTP_STATUS=$(tail -n1 "${LOG_DIR}/$service.log")

    if [ "$HTTP_STATUS" = "200" ]; then
        echo "✅ User deletion successful (HTTP 200)"

        # Verify user is no longer in the list
        > "${LOG_DIR}/$service.log"
        exec_in_container $service curl -k -s -u "$WEBUI_USERNAME:$WEBUI_PASSWORD" https://ssh-server/users
        USER_PAGE_CONTENT=$(cat "${LOG_DIR}/$service.log")

        if ! echo "$USER_PAGE_CONTENT" | grep -q "testuser"; then
            return 0
        else
            echo "❌ User still appears in user list after deletion"
            return 1
        fi
    else
        echo "❌ User deletion failed with status: $HTTP_STATUS (expected 200)"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}

test_ssh_user_authentication_after_deletion() {
    local service="ssh-client"
    > "${LOG_DIR}/$service.log"

    # Try to connect with the deleted user credentials (should fail)
    exec_in_container $service timeout 3s sshpass -p 'testpassword123' ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        testuser@ssh-server -p 22 \
        "echo 'SSH connection successful'" 2>/dev/null

    # Should NOT contain success message
    if ! grep -q "SSH connection successful" "${LOG_DIR}/$service.log"; then
        return 0
    else
        echo "❌ SSH authentication unexpectedly succeeded for deleted user"
        cat "${LOG_DIR}/$service.log"
        return 1
    fi
}


run_test "Mock server responding from http-client" test_mock_server
run_test "SSH server accepts connections" test_ssh_connection
run_test "SSH Tunnel URL Parsing" test_ssh_tunnel_url_parsing
run_test "E2E Integration" test_http_tunneling
run_test "WebUI HTTP returns 404" test_webui_http_404
run_test "WebUI HTTPS rejects wrong credentials" test_webui_https_wrong_credentials
run_test "WebUI HTTPS rejects no credentials" test_webui_https_no_credentials
run_test "WebUI HTTPS accepts correct credentials" test_webui_https_correct_credentials
run_test "WebUI displays active tunnels" test_webui_tunnel_display

# User Management Tests
run_test "WebUI user creation" test_webui_user_creation
run_test "WebUI user creation duplicate rejection" test_webui_user_creation_duplicate
run_test "WebUI user list displays created user" test_webui_user_list
run_test "SSH authentication with created user" test_ssh_user_authentication
run_test "SSH tunnel creation with created user" test_ssh_user_tunnel_creation
run_test "WebUI user deletion" test_webui_user_deletion
run_test "SSH authentication rejected after user deletion" test_ssh_user_authentication_after_deletion





# Final Results
echo ""
echo "🎯 ============================================"
echo "🎯 E2E TEST ORCHESTRATOR RESULTS"
echo "🎯 ============================================"
echo "✅ Tests Passed: $TESTS_PASSED"
echo "❌ Tests Failed: $TESTS_FAILED"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo "🎉 ████████████████████████████████████████"
    echo "🎉 ██  ALL E2E TESTS PASSED!           ██"
    echo "🎉 ████████████████████████████████████████"
    echo ""
    exit 0
else
    echo ""
    echo "❌ ████████████████████████████████████████"
    echo "❌ ██  SOME E2E TESTS FAILED!         ██"
    echo "❌ ████████████████████████████████████████"
    echo ""
    echo "Failed tests:"
    for test in "${FAILED_TESTS[@]}"; do
        echo "  - $test"
    done
    echo ""
    docker compose -f "$COMPOSE_FILE" logs -n20
    exit 1
fi