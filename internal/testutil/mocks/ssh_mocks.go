// Package mocks provides common mock implementations for testing
package mocks

import (
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSHChannel is a mock implementation of ssh.Channel for testing
type SSHChannel struct {
	Buffer      []byte
	closed      bool
	closeCalled bool
	mu          sync.Mutex
}

// Read implements ssh.Channel
func (m *SSHChannel) Read(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return 0, fmt.Errorf("channel closed")
	}
	if len(m.Buffer) == 0 {
		return 0, nil
	}
	n := copy(data, m.Buffer)
	m.Buffer = m.Buffer[n:]
	return n, nil
}

// Write implements ssh.Channel
func (m *SSHChannel) Write(data []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return 0, fmt.Errorf("channel closed")
	}
	m.Buffer = append(m.Buffer, data...)
	return len(data), nil
}

// Close implements ssh.Channel
func (m *SSHChannel) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.closed = true
	m.closeCalled = true
	return nil
}

// CloseWrite implements ssh.Channel
func (m *SSHChannel) CloseWrite() error {
	return nil
}

// SendRequest implements ssh.Channel
func (m *SSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return false, nil
}

// Stderr implements ssh.Channel
func (m *SSHChannel) Stderr() io.ReadWriter {
	return nil
}

// IsClosed returns whether the channel has been closed
func (m *SSHChannel) IsClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// SSHConn is a mock implementation of ssh.Conn for testing
type SSHConn struct {
	UserValue      string
	RemoteAddress  net.Addr
	LocalAddress   net.Addr
	SessionIDValue []byte
	OpenChannelFunc func(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error)
}

// User implements ssh.Conn
func (m *SSHConn) User() string {
	if m.UserValue != "" {
		return m.UserValue
	}
	return "test-user"
}

// SessionID implements ssh.Conn
func (m *SSHConn) SessionID() []byte {
	if m.SessionIDValue != nil {
		return m.SessionIDValue
	}
	return []byte("test-session-id")
}

// ClientVersion implements ssh.Conn
func (m *SSHConn) ClientVersion() []byte {
	return []byte("SSH-2.0-TestClient")
}

// ServerVersion implements ssh.Conn
func (m *SSHConn) ServerVersion() []byte {
	return []byte("SSH-2.0-TestServer")
}

// RemoteAddr implements ssh.Conn
func (m *SSHConn) RemoteAddr() net.Addr {
	if m.RemoteAddress != nil {
		return m.RemoteAddress
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22222}
}

// LocalAddr implements ssh.Conn
func (m *SSHConn) LocalAddr() net.Addr {
	if m.LocalAddress != nil {
		return m.LocalAddress
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}

// Close implements ssh.Conn
func (m *SSHConn) Close() error {
	return nil
}

// SendRequest implements ssh.Conn
func (m *SSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, nil
}

// OpenChannel implements ssh.Conn
func (m *SSHConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	if m.OpenChannelFunc != nil {
		return m.OpenChannelFunc(name, data)
	}
	return nil, nil, fmt.Errorf("not implemented")
}

// Wait implements ssh.Conn
func (m *SSHConn) Wait() error {
	return nil
}

// ConnMetadata is a mock implementation of ssh.ConnMetadata for testing
type ConnMetadata struct {
	UserValue          string
	SessionIDValue     []byte
	ClientVersionValue []byte
	ServerVersionValue []byte
	RemoteAddress      net.Addr
	LocalAddress       net.Addr
}

// User implements ssh.ConnMetadata
func (m *ConnMetadata) User() string {
	if m.UserValue != "" {
		return m.UserValue
	}
	return "test-user"
}

// SessionID implements ssh.ConnMetadata
func (m *ConnMetadata) SessionID() []byte {
	if m.SessionIDValue != nil {
		return m.SessionIDValue
	}
	return []byte("test-session-id")
}

// ClientVersion implements ssh.ConnMetadata
func (m *ConnMetadata) ClientVersion() []byte {
	if m.ClientVersionValue != nil {
		return m.ClientVersionValue
	}
	return []byte("SSH-2.0-TestClient")
}

// ServerVersion implements ssh.ConnMetadata
func (m *ConnMetadata) ServerVersion() []byte {
	if m.ServerVersionValue != nil {
		return m.ServerVersionValue
	}
	return []byte("SSH-2.0-TestServer")
}

// RemoteAddr implements ssh.ConnMetadata
func (m *ConnMetadata) RemoteAddr() net.Addr {
	if m.RemoteAddress != nil {
		return m.RemoteAddress
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22222}
}

// LocalAddr implements ssh.ConnMetadata
func (m *ConnMetadata) LocalAddr() net.Addr {
	if m.LocalAddress != nil {
		return m.LocalAddress
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}