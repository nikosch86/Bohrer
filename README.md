# Bohrer SSH Tunnel Server

A secure SSH tunneling server that provides instant HTTPS URLs for your local services. Connect via SSH and get a public subdomain that routes traffic to your local development server.

## Quick Start

### For Users

```bash
# Connect with SSH key (username must be "tunnel")
ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222 -i ~/.ssh/id_rsa

# OR connect with username/password (created via WebUI)
ssh -R 0:localhost:3000 username@your-server.com -p 2222

# Your service is now accessible at the provided URL:
# Tunnel created: http://happy-cloud-42.your-server.com
```

**Note**: Server must be publicly accessible to share tunnels. Authentication requires either SSH keys or WebUI-created credentials.

### For Server Administrators

#### Prerequisites
- Docker and Docker Compose
- For production: Public server, domain with wildcard DNS (*.domain.com), open ports 2222/80/443

#### Quick Setup

```bash
# 1. Setup
git clone https://github.com/your-repo/bohrer-go.git && cd bohrer-go
cp .env.example .env
# Edit .env: Set DOMAIN, ACME_EMAIL, etc.

# 2. Start server
docker compose up -d

# 3. Get admin credentials and access WebUI
docker compose logs ssh-tunnel
# Access: https://localhost or https://your-domain.com

# 4. Create authentication (in WebUI)
# - Users: "Manage Users" → Create username/password
# - SSH Keys: "SSH Keys" → Add public keys

# 5. Test tunnel
ssh -R 0:localhost:3000 user@your-domain.com -p 2222
```


## How It Works

```
┌─────────────────┐    SSH Tunnel    ┌──────────────────┐    HTTP Proxy    ┌─────────────────┐
│   Your Local    │ ───────────────▶ │  Bohrer Server   │ ───────────────▶ │   Internet      │
│   Service       │         :2222    │  + WebUI         │       :80        │   Users         │
│   localhost:3000│ ◀─────────────── │  your-server.com │ ◀──────────────  │                 │
└─────────────────┘                  └──────────────────┘                  └─────────────────┘
                                            │
                                            ▼
                                      Subdomain Generator
                                      happy-cloud-42.your-server.com
```

1. **SSH Connection**: You connect via SSH with remote port forwarding (`-R`)
2. **Subdomain Generation**: Server creates a unique subdomain (e.g., `happy-cloud-42.your-server.com`)
3. **HTTP Proxy**: Server routes HTTP requests from the subdomain to your SSH tunnel
4. **Secure Access**: Your local service becomes accessible via the public subdomain
5. **WebUI Management**: Visit the root domain to manage tunnels and users

## Network Requirements

| Environment | Requirements | Access |
|------------|--------------|---------|
| **Local Development** | `localhost` domain, Docker | Same machine only |
| **Production** | Public IP, Domain with wildcard DNS (*.domain.com), Ports 2222/80/443 open | Internet accessible |

## WebUI Management

Access at `https://your-domain.com` (or `https://localhost` for development)

**Features:**
- 📊 **Dashboard**: View active tunnels with real-time updates
- 👥 **User Management**: Create/delete SSH users with passwords
- 🔑 **SSH Key Management**: Add/remove SSH public keys
- 🔒 **Authentication**: Basic auth with auto-generated or configured admin credentials

## Authentication

### Password Authentication
Create users via WebUI (`https://your-domain.com`) → "Manage Users"

### SSH Key Authentication

**Via WebUI (Recommended):**
1. Go to "SSH Keys" in WebUI
2. Add your public key with a name
3. Connect using username "tunnel": `ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222`

**Via Command Line:**
```bash
# Add key to authorized_keys
docker compose run --rm ssh-tunnel sh -c "mkdir -p /data && echo '$(cat ~/.ssh/id_rsa.pub)' > /data/authorized_keys"
```

## Common Usage Examples

```bash
# Basic tunnel
ssh -R 0:localhost:3000 user@your-server.com -p 2222
```

Works with any HTTP service: React, Flask, Django, static files, etc.

## Server Configuration

### Environment Variables

#### Core Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Base domain for tunnel subdomains (e.g., subdomain.DOMAIN) |
| `LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARN, ERROR, FATAL |

#### SSL/ACME Certificate Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `ACME_EMAIL` | `test@example.com` | Email for Let's Encrypt registration (empty = use self-signed) |
| `ACME_STAGING` | `true` | Use Let's Encrypt staging (true) or production (false) - **SAFETY**: Always defaults to staging |
| `ACME_DIRECTORY_URL` | `""` | Custom ACME server URL (empty = Let's Encrypt) |
| `ACME_FORCE_LOCAL` | `false` | Force ACME even for local domains (for custom PKI) |
| `ACME_CERT_PATH` | `/data/certs/fullchain.pem` | Certificate file path (inside container) |
| `ACME_KEY_PATH` | `/data/certs/key.pem` | Private key file path (inside container) |
| `ACME_CHALLENGE_DIR` | `/data/acme-challenge` | HTTP-01 challenge directory |
| `ACME_RENEWAL_DAYS` | `30` | Certificate renewal threshold (days before expiry) |
| `SKIP_ACME` | `false` | Skip ACME entirely and use self-signed certificates |

#### Port Configuration  
| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_PORT` | `22` | SSH server internal port (inside container) |
| `HTTP_PORT` | `80` | HTTP proxy internal port (inside container) |
| `HTTPS_PORT` | `443` | HTTPS proxy internal port (inside container) |
| `SSH_EXTERNAL_PORT` | `SSH_PORT` | SSH server external port (Docker host) |
| `HTTP_EXTERNAL_PORT` | `HTTP_PORT` | HTTP proxy external port (Docker host) |
| `HTTPS_EXTERNAL_PORT` | `HTTPS_PORT` | HTTPS proxy external port (Docker host) |

#### SSH Authentication
| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_AUTHORIZED_KEYS` | `/data/authorized_keys` | Path to SSH authorized keys file |

#### User Storage Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `USER_STORAGE_TYPE` | `file` | Storage backend: "file" (persistent) or "memory" (temporary) |
| `USER_STORAGE_PATH` | `/data/users.json` | Path to user storage file (when using file backend) |

#### WebUI Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `WEBUI_USERNAME` | _(empty)_ | WebUI admin username (empty = auto-generate) |
| `WEBUI_PASSWORD` | _(empty)_ | WebUI admin password (empty = auto-generate) |

### Certificate Options

| Environment | Configuration | Result |
|------------|--------------|---------|
| **Development** | `DOMAIN=localhost`, no `ACME_EMAIL` | Self-signed certificate |
| **Production** | Valid domain, `ACME_EMAIL`, `ACME_STAGING=false` | Let's Encrypt certificate |
| **Testing** | Valid domain, `ACME_EMAIL`, `ACME_STAGING=true` | Let's Encrypt staging |
| **Internal CA** | `ACME_DIRECTORY_URL`, `ACME_FORCE_LOCAL=true` | Custom ACME server |

**⚠️ Production Rate Limits**: Let's Encrypt enforces strict limits (5 auth failures/hour, 50 certs/week per domain). Always test with staging first!

### Certificate Decision Logic

The server chooses certificate type based on this priority:

1. **No ACME Email** → Always use self-signed certificates
2. **Local Domain + No Custom ACME URL** → Use self-signed certificates  
3. **Local Domain + Custom ACME URL** → Use custom ACME server
4. **Public Domain** → Use Let's Encrypt (staging or production)
5. **ACME_FORCE_LOCAL=true** → Force ACME even for local domains

**Local domains** are detected as: `localhost`, `*.local`, `*.lan`, `*.home`, `*.internal`, `*.dev`, `*.test`, or private IP addresses.

### ACME Rate Limiting

The server includes **built-in rate limiting** to protect against Let's Encrypt production rate limits:

#### Rate Limits (Production Only)
- **Authorization Failures**: 5 per hostname per hour
- **New Orders**: 300 per account every 3 hours
- **Domain Certificates**: 50 per domain every 7 days

#### Features
- **Automatic Protection**: Checks limits before making ACME requests
- **Staging Bypass**: No limits applied for staging environment
- **Custom ACME Bypass**: No limits for custom ACME directories
- **Error Prevention**: Clear error messages when limits would be exceeded
- **Memory-based**: Tracks usage in application memory (resets on restart)

#### Rate Limit Status
The rate limiting status can be monitored programmatically through the ACME client's `GetRateLimitStatus()` method, which returns current usage for all tracked limits.


### DNS Configuration

For production deployment, configure DNS:
```
# A record
your-domain.com.     IN  A  YOUR_SERVER_IP

# Wildcard for subdomains  
*.your-domain.com.   IN  A  YOUR_SERVER_IP
```

## Development Setup (For Contributors)

### Prerequisites
- Docker and Docker Compose (the project is supposed to run in containers)
- Go 1.24 or later (optional - only if you want to run tests locally)
- The Makefile supports both Docker-based and local Go testing

### Running Tests
```bash
# Unit tests with coverage (can run locally with Go 1.24+)
make test

# Run tests for specific package
make test-ssh     # SSH package tests
make test-proxy   # Proxy package tests
make test-webui   # WebUI package tests

# End-to-end tests (requires Docker)
make e2e

# Generate coverage report
make coverage     # Generates coverage.html

# Start development environment
make dev-up

# View logs
docker compose logs ssh-tunnel
```

**Note**: End-to-end tests automatically generate temporary SSH keys for testing and clean them up afterward. No credentials are stored in the repository.

### Project Structure
```
├── cmd/server/          # Main application
├── internal/
│   ├── acme/           # ACME/Let's Encrypt integration
│   ├── certs/          # Certificate generation utilities
│   ├── common/         # Shared utilities (mutex, URL builder, cert validator)
│   ├── config/         # Configuration management
│   ├── fileutil/       # File operations with atomic writes
│   ├── logger/         # Structured logging
│   ├── proxy/          # HTTP/HTTPS reverse proxy
│   ├── ssh/            # SSH server implementation
│   ├── testutil/       # Test utilities and shared mocks
│   └── webui/          # Web UI and user management
├── test/               # Test utilities and scripts
├── docker-compose.yml  # Development environment
└── Makefile           # Build and test automation
```

## Troubleshooting

### Connection Issues

**"Connection refused" on SSH:**
```bash
# Check if server is running
nc -zv your-server.com 2222

# Check server logs
docker compose logs ssh-tunnel
```

**"Permission denied" on SSH:**
- **For password auth**: Ensure the username exists in WebUI and password is correct
  - Check WebUI at `https://your-server.com` → "Manage Users"
  - Verify the username was created successfully
  - Try creating a new user if needed
- **For key auth**: Check these common issues:
  ```bash
  # Verify your public key is in authorized_keys inside the container
  docker compose exec ssh-tunnel cat /data/authorized_keys
  
  # Check file permissions inside container
  docker compose exec ssh-tunnel ls -la /data/authorized_keys
  
  # Test SSH key locally
  ssh-keygen -l -f ~/.ssh/id_rsa.pub
  
  # Check server logs for specific auth errors
  docker compose logs ssh-tunnel | grep -i auth
  
  # Verify the authorized_keys file exists in the volume
  docker compose exec ssh-tunnel ls -la /data/
  ```

**SSH Key Authentication Issues:**
- **Key not found**: Ensure `SSH_AUTHORIZED_KEYS` path is correct
- **Permission errors**: Check that the container can read the authorized_keys file
- **Wrong key format**: Verify your public key is in the correct OpenSSH format
- **Multiple keys**: Add one key per line in the authorized_keys file
- **Path issues**: Make sure the Docker volume mounts the correct directory

### Tunnel Issues

**Tunnel created but URL not accessible:**
```bash
# Check if HTTP proxy is running
curl -I http://your-server.com

# Test with subdomain
curl -H "Host: happy-cloud-42.your-server.com" http://your-server.com
```

**Local service not responding:**
- Verify your local service is running and accessible
- Check the port number matches what you specified in SSH command
- Test local service directly: `curl localhost:YOUR_PORT`

### Server Issues

**Server won't start:**
```bash
# Check port conflicts
netstat -tlnp | grep :2222
netstat -tlnp | grep :80

# Check logs for specific errors
docker compose logs ssh-tunnel
```

## Contributing

### Development Workflow
1. **Tests first**: Write tests before implementing features
2. **Docker-based**: All development happens in containers
3. **High coverage**: Maintain >85% test coverage
4. **TDD approach**: Red → Green → Refactor

### Running the Full Test Suite
```bash
# Unit tests
make test

# Integration tests  
make e2e

# Check coverage
open coverage.html
```

## License

MIT License - see [LICENSE](LICENSE) file for details.