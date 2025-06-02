package ssh

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"bohrer-go/internal/config"
	"bohrer-go/internal/testutil/mocks"
	"golang.org/x/crypto/ssh"
)

// mockChannel implements ssh.Channel for testing
type mockChannel struct {
	data       chan []byte
	closed     bool
	closeError error
	mu         sync.Mutex
}

func (m *mockChannel) Read(data []byte) (int, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	
	if closed {
		return 0, io.EOF
	}
	select {
	case d, ok := <-m.data:
		if !ok {
			return 0, io.EOF
		}
		copy(data, d)
		return len(d), nil
	default:
		return 0, nil
	}
}

func (m *mockChannel) Write(data []byte) (int, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	
	if closed {
		return 0, fmt.Errorf("channel closed")
	}
	select {
	case m.data <- data:
		return len(data), nil
	default:
		// Channel full, just return success
		return len(data), nil
	}
}

func (m *mockChannel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.closed {
		m.closed = true
		close(m.data)
	}
	return m.closeError
}

func (m *mockChannel) CloseWrite() error                { return nil }
func (m *mockChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}
func (m *mockChannel) Stderr() io.ReadWriter { return nil }

// TestForwardConnectionThroughSSHAdvanced tests advanced SSH forwarding functionality
func TestForwardConnectionThroughSSHAdvanced(t *testing.T) {
	// Create a test SSH server
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   2222,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	server := NewServer(cfg)

	// Create a mock SSH connection
	mockConn := &mocks.SSHConn{
		OpenChannelFunc: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
			if name != "forwarded-tcpip" {
				return nil, nil, fmt.Errorf("unexpected channel type: %s", name)
			}
			// Return a mock channel
			mockChan := &mockChannel{
				data: make(chan []byte, 100),
			}
			reqs := make(chan *ssh.Request)
			close(reqs) // No requests expected
			return mockChan, reqs, nil
		},
	}

	// Create a test TCP listener
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()
	testPort := listener.Addr().(*net.TCPAddr).Port

	// Start a simple echo server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}(conn)
		}
	}()

	// Test cases
	t.Run("successful forwarding", func(t *testing.T) {
		// Connect to our echo server
		localConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", testPort))
		if err != nil {
			t.Fatalf("Failed to connect to test server: %v", err)
		}

		// Run forwardConnectionThroughSSH in a goroutine
		done := make(chan bool)
		go func() {
			server.forwardConnectionThroughSSH(localConn, mockConn, testPort)
			done <- true
		}()

		// Give it time to set up
		time.Sleep(10 * time.Millisecond)

		// Write some test data
		testData := []byte("Hello, SSH forwarding!")
		localConn.Write(testData)

		// Wait for forwarding to complete
		select {
		case <-done:
			// Success
		case <-time.After(100 * time.Millisecond):
			t.Error("Forwarding didn't complete in time")
		}
	})

	t.Run("nil ssh connection", func(t *testing.T) {
		localConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", testPort))
		if err != nil {
			t.Fatalf("Failed to connect to test server: %v", err)
		}

		// This should return immediately without panic
		server.forwardConnectionThroughSSH(localConn, nil, testPort)
		
		// Connection should be closed
		buf := make([]byte, 1)
		_, err = localConn.Read(buf)
		if err == nil {
			t.Error("Expected connection to be closed")
		}
	})

	t.Run("channel open failure", func(t *testing.T) {
		failConn := &mocks.SSHConn{
			OpenChannelFunc: func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
				return nil, nil, fmt.Errorf("failed to open channel")
			},
		}

		localConn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", testPort))
		if err != nil {
			t.Fatalf("Failed to connect to test server: %v", err)
		}

		// This should handle the error gracefully
		server.forwardConnectionThroughSSH(localConn, failConn, testPort)
		
		// Connection should be closed
		buf := make([]byte, 1)
		_, err = localConn.Read(buf)
		if err == nil {
			t.Error("Expected connection to be closed")
		}
	})
}


// TestHandleDirectTcpipImproved tests additional scenarios for handleDirectTcpip
func TestHandleDirectTcpipImproved(t *testing.T) {
	cfg := &config.Config{
		Domain:    "test.local",
		SSHPort:   2222,
		HTTPPort:  8080,
		HTTPSPort: 8443,
	}
	server := NewServer(cfg)

	// Start a test TCP server on dynamic port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()
	testPort := listener.Addr().(*net.TCPAddr).Port

	// Add a tunnel to the server
	server.mutex.Lock()
	server.tunnels["test-tunnel"] = &Tunnel{
		Subdomain:   "test-tunnel",
		LocalPort:   testPort,
		Channel:     nil,
		Connections: make(map[string]net.Conn),
		Listener:    nil,
	}
	server.mutex.Unlock()

	// Test successful connection cleanup
	t.Run("cleanup connections on completion", func(t *testing.T) {
		// Create mock new channel with valid direct-tcpip payload
		// The payload needs more data for the source host/port as well
		hostBytes := []byte("localhost")
		payload := make([]byte, 0, 100)
		
		// Target host length and host
		payload = append(payload, 0, 0, 0, byte(len(hostBytes)))
		payload = append(payload, hostBytes...)
		
		// Target port
		payload = append(payload, byte(testPort>>24), byte(testPort>>16), byte(testPort>>8), byte(testPort))
		
		// Source host length and host (originator)
		originHost := []byte("127.0.0.1")
		payload = append(payload, 0, 0, 0, byte(len(originHost)))
		payload = append(payload, originHost...)
		
		// Source port
		payload = append(payload, 0, 0, 0x12, 0x34) // Some arbitrary port

		acceptCalled := false
		mockNewChannel := &mockForwardNewChannel{
			channelType: "direct-tcpip",
			extraData:   payload,
			acceptFunc: func() (ssh.Channel, <-chan *ssh.Request, error) {
				acceptCalled = true
				ch := &mockChannel{
					data:   make(chan []byte, 100),
					closed: false,
				}
				reqs := make(chan *ssh.Request)
				go func() {
					// Close after a short delay to simulate connection end
					time.Sleep(10 * time.Millisecond)
					ch.Close()
					close(reqs)
				}()
				return ch, reqs, nil
			},
		}

		// Handle connections on the test server
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				// Just close the connection immediately
				conn.Close()
			}
		}()

		// Call handleDirectTcpip
		server.handleDirectTcpip(mockNewChannel)

		// Give it time to process
		time.Sleep(50 * time.Millisecond)

		// Verify connection was cleaned up
		server.mutex.RLock()
		tunnel := server.tunnels["test-tunnel"]
		connCount := len(tunnel.Connections)
		server.mutex.RUnlock()

		if connCount != 0 {
			t.Errorf("Expected 0 connections after cleanup, got %d", connCount)
		}

		if !acceptCalled {
			t.Error("Expected Accept to be called")
		}
	})
}

// mockForwardNewChannel implements ssh.NewChannel for testing
type mockForwardNewChannel struct {
	channelType string
	extraData   []byte
	acceptFunc  func() (ssh.Channel, <-chan *ssh.Request, error)
	rejectFunc  func(reason ssh.RejectionReason, message string) error
}

func (m *mockForwardNewChannel) ChannelType() string {
	return m.channelType
}

func (m *mockForwardNewChannel) ExtraData() []byte {
	return m.extraData
}

func (m *mockForwardNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	if m.acceptFunc != nil {
		return m.acceptFunc()
	}
	return nil, nil, fmt.Errorf("not implemented")
}

func (m *mockForwardNewChannel) Reject(reason ssh.RejectionReason, message string) error {
	if m.rejectFunc != nil {
		return m.rejectFunc(reason, message)
	}
	return nil
}