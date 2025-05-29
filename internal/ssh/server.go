package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"sync"

	"github.com/hoffmann/bohrer-go/internal/config"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	config   *config.Config
	hostKey  ssh.Signer
	tunnels  map[string]*Tunnel
	mutex    sync.RWMutex
}

type Tunnel struct {
	Subdomain string
	LocalPort int
	Conn      net.Conn
}

func NewServer(cfg *config.Config) *Server {
	hostKey, err := generateHostKey()
	if err != nil {
		log.Fatalf("Failed to generate host key: %v", err)
	}

	return &Server{
		config:  cfg,
		hostKey: hostKey,
		tunnels: make(map[string]*Tunnel),
	}
}

func (s *Server) Start() error {
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "tunnel" && string(pass) == "test123" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}
	sshConfig.AddHostKey(s.hostKey)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.SSHPort))
	if err != nil {
		return fmt.Errorf("failed to listen on SSH port: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept SSH connection: %v", err)
			continue
		}

		go s.handleConnection(conn, sshConfig)
	}
}

func (s *Server) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	log.Printf("SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.User())

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				if req.Type == "tcpip-forward" {
					subdomain := generateSubdomain()
					log.Printf("Created tunnel with subdomain: %s", subdomain)
					fmt.Fprintf(channel, "Tunnel ready: http://%s.%s:%d\n", subdomain, s.config.Domain, s.config.HTTPPort)
				}
				req.Reply(req.Type == "tcpip-forward", nil)
			}
		}(requests)

		go func() {
			io.Copy(channel, channel)
			channel.Close()
		}()
	}
}

func generateHostKey() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})

	return ssh.ParsePrivateKey(keyPEM)
}

func generateSubdomain() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = chars[mathrand.Intn(len(chars))]
	}
	return string(b)
}