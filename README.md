# Bohrer SSH Tunnel Server

A secure SSH tunneling server that provides instant HTTPS URLs for your local services. Connect via SSH and get a public subdomain that routes traffic to your local development server.

## Quick Start

### For Users (Connecting to an Existing Server)

1. **Connect and create a tunnel:**
   ```bash
   ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222
   ```

2. **Access your service:**
   ```
   Tunnel created: http://abc123.your-server.com:8080
   ```
   Your local service running on port 3000 is now accessible at the provided URL.

### For Server Administrators (Running Your Own Server)

#### Prerequisites
- Docker and Docker Compose
- Domain name pointing to your server (for production HTTPS)

#### Installation

1. **Clone and configure:**
   ```bash
   git clone https://github.com/your-org/bohrer-go.git
   cd bohrer-go
   
   # Configure your domain
   export DOMAIN=your-domain.com
   export ACME_EMAIL=your-email@domain.com
   ```

2. **Configure environment (recommended):**
   ```bash
   # Copy example configuration
   cp .env.example .env
   
   # Edit .env with your settings
   nano .env
   ```

3. **Set up SSH key authentication (recommended for production):**
   ```bash
   # Option 1: Add your existing public key to the container
   docker compose run --rm ssh-tunnel sh -c "mkdir -p /data && echo '$(cat ~/.ssh/id_rsa.pub)' > /data/authorized_keys"
   
   # Option 2: Create a new key specifically for the tunnel
   ssh-keygen -t rsa -b 4096 -f ./tunnel_key
   docker compose run --rm ssh-tunnel sh -c "mkdir -p /data && echo '$(cat ./tunnel_key.pub)' > /data/authorized_keys"
   ```
   
   **Note**: The server uses Docker named volumes for data persistence. SSH keys and certificates are stored in the `ssh_tunnel_data` volume.

4. **Start the server:**
   ```bash
   docker compose up -d
   ```

5. **Verify it's running:**
   ```bash
   docker compose ps
   docker compose logs ssh-tunnel
   ```

## How It Works

```
┌─────────────────┐    SSH Tunnel    ┌──────────────────┐    HTTP Proxy    ┌─────────────────┐
│   Your Local   │ ────────────────▶ │  Bohrer Server   │ ────────────────▶ │   Internet      │
│   Service       │                  │                  │                  │   Users         │
│   localhost:3000│ ◀──────────────── │  your-server.com │ ◀──────────────── │                 │
└─────────────────┘                  └──────────────────┘                  └─────────────────┘
                                            │
                                            ▼
                                      Subdomain Generator
                                      abc123.your-server.com
```

1. **SSH Connection**: You connect via SSH with remote port forwarding (`-R`)
2. **Subdomain Generation**: Server creates a unique subdomain (e.g., `abc123.your-server.com`)
3. **HTTP Proxy**: Server routes HTTP requests from the subdomain to your SSH tunnel
4. **Secure Access**: Your local service becomes accessible via the public subdomain

## User Guide

### Basic Usage

**Create a tunnel for a web server:**
```bash
# Your local server is running on port 3000
ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222
```

**Create a tunnel for a specific port:**
```bash
# Forward specific port 8080 to your local port 3000
ssh -R 8080:localhost:3000 tunnel@your-server.com -p 2222
```

**Keep tunnel alive in background:**
```bash
# Use -f to run in background, -N to not execute commands
ssh -f -N -R 0:localhost:3000 tunnel@your-server.com -p 2222
```

### Authentication

The server supports both password and SSH key authentication:

#### Password Authentication (Development)
- **Username**: `tunnel`
- **Password**: `test123`
- **Usage**: Suitable for development and testing

#### SSH Key Authentication (Production)
For production deployments, use SSH key authentication:

**1. Generate SSH Key Pair (if you don't have one):**
```bash
ssh-keygen -t rsa -b 4096 -C "your-email@example.com"
# This creates ~/.ssh/id_rsa (private) and ~/.ssh/id_rsa.pub (public)
```

**2. Create Authorized Keys File:**
```bash
# Add your public key to the container volume
docker compose run --rm ssh-tunnel sh -c "mkdir -p /data && echo '$(cat ~/.ssh/id_rsa.pub)' > /data/authorized_keys"

# Or add multiple keys:
docker compose run --rm ssh-tunnel sh -c "mkdir -p /data && cat > /data/authorized_keys" << EOF
$(cat user1_key.pub)
$(cat user2_key.pub)
EOF
```

**3. Configure Server Environment:**
The server automatically uses `/data/authorized_keys` inside the container. No additional configuration needed when using the default Docker Compose setup.

**4. Connect with SSH Key:**
```bash
# Use your private key to connect
ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222 -i ~/.ssh/id_rsa

# Or if using ssh-agent:
ssh-add ~/.ssh/id_rsa
ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222
```

**Authorized Keys Format:**
The authorized_keys file follows standard SSH format:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... user1@example.com
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user2@example.com
# Comments start with #
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user3@example.com
```

> **Security Note**: In production, consider disabling password authentication entirely by removing the PasswordCallback in your deployment configuration.

### Supported Services

Works with any HTTP service:
- **Web applications** (React, Vue, Angular dev servers)
- **API servers** (Node.js, Python Flask/Django, Go servers)
- **Static file servers** (nginx, Apache, Python SimpleHTTPServer)
- **Development tools** (Webpack dev server, Vite, etc.)

### Examples

**React Development Server:**
```bash
# Start your React app
npm start  # Usually runs on localhost:3000

# In another terminal, create tunnel
ssh -R 0:localhost:3000 tunnel@your-server.com -p 2222
# Share the provided URL with team members or clients
```

**Python Flask API:**
```bash
# Start your Flask app
flask run --port 5000

# Create tunnel for Flask
ssh -R 0:localhost:5000 tunnel@your-server.com -p 2222
```

**Static Website:**
```bash
# Serve static files
python -m http.server 8000

# Create tunnel
ssh -R 0:localhost:8000 tunnel@your-server.com -p 2222
```

## Server Configuration

### Environment Variables

#### Core Configuration
| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `localhost` | Base domain for tunnel subdomains (e.g., subdomain.DOMAIN) |

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

### Certificate Configuration Scenarios

#### Development (Self-Signed Certificates)
```bash
# .env
DOMAIN=localhost
ACME_EMAIL=                    # Empty = disable ACME
ACME_STAGING=true
HTTP_EXTERNAL_PORT=8080
HTTPS_EXTERNAL_PORT=8443
```
**Result**: Generates wildcard self-signed certificate for `*.localhost`

#### Production (Let's Encrypt)
```bash
# .env  
DOMAIN=tunnel.yourdomain.com
ACME_EMAIL=admin@yourdomain.com
ACME_STAGING=false            # EXPLICIT production setting required
HTTP_EXTERNAL_PORT=80
HTTPS_EXTERNAL_PORT=443
```
**Result**: Uses Let's Encrypt production server for real certificates

**⚠️ PRODUCTION SAFETY & RATE LIMITING**: 
- **Always test with staging first** (`ACME_STAGING=true`)
- **Built-in rate limiting** protects against Let's Encrypt production limits:
  - 5 authorization failures per hostname per hour
  - 300 new orders per account every 3 hours  
  - 50 certificates per domain every 7 days
- **Automatic enforcement**: Rate limits are checked before ACME requests
- Only set `ACME_STAGING=false` for real production deployments
- Requires valid public domain with proper DNS setup

#### Staging/Testing (Let's Encrypt Staging)
```bash
# .env
DOMAIN=tunnel-test.yourdomain.com
ACME_EMAIL=admin@yourdomain.com
ACME_STAGING=true             # Use staging Let's Encrypt
```
**Result**: Uses Let's Encrypt staging server (higher rate limits, fake certificates)

#### Custom PKI/Internal CA
```bash
# .env
DOMAIN=tunnel.company.local
ACME_EMAIL=admin@company.local
ACME_DIRECTORY_URL=https://ca.company.local/acme/acme/directory
ACME_FORCE_LOCAL=true         # Force ACME for local domains
ACME_STAGING=false
```
**Result**: Uses your internal ACME server (e.g., Step CA, Smallstep) even for local domains

#### Mixed Environment (Custom ACME + Local Fallback)
```bash
# .env
DOMAIN=dev.company.local
ACME_EMAIL=admin@company.local
ACME_DIRECTORY_URL=https://ca.company.local/acme/acme/directory
ACME_FORCE_LOCAL=false        # Don't force - fallback to self-signed if ACME fails
```
**Result**: Tries custom ACME server first, falls back to self-signed if it fails

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

### Docker Compose Configuration

The server uses environment variables for flexible port configuration:

```yaml
# docker-compose.yml
services:
  ssh-tunnel:
    build: .
    ports:
      - "${SSH_EXTERNAL_PORT:-2222}:22"          # SSH port (external:internal)
      - "${HTTP_EXTERNAL_PORT:-8080}:80"         # HTTP port (external:internal)
      - "${HTTPS_EXTERNAL_PORT:-8443}:443"       # HTTPS port (external:internal)
    environment:
      - DOMAIN=your-domain.com
      - ACME_EMAIL=admin@your-domain.com
      - ACME_STAGING=false
      - SSH_PORT=22                               # Standard SSH port inside container
      - HTTP_PORT=80                              # Standard HTTP port inside container
      - HTTPS_PORT=443                            # Standard HTTPS port inside container
      - HTTP_EXTERNAL_PORT=${HTTP_EXTERNAL_PORT:-8080}
      - HTTPS_EXTERNAL_PORT=${HTTPS_EXTERNAL_PORT:-8443}
      - SSH_AUTHORIZED_KEYS=/data/authorized_keys
    volumes:
      - ssh_tunnel_data:/data   # Named volume for certificate and SSH keys storage
    restart: unless-stopped

volumes:
  ssh_tunnel_data:
```

### Environment Configuration

Create a `.env` file to customize ports and settings:

```bash
# .env file
DOMAIN=yourdomain.com
ACME_EMAIL=admin@yourdomain.com
ACME_STAGING=false

# External ports (what users access)
SSH_EXTERNAL_PORT=2222
HTTP_EXTERNAL_PORT=80     # Standard HTTP port
HTTPS_EXTERNAL_PORT=443   # Standard HTTPS port

# Internal ports (inside container) - standard ports, usually don't change these
HTTP_PORT=80
HTTPS_PORT=443
SSH_PORT=22
```

### Port Configuration Examples

**Development (avoiding conflicts):**
```bash
# .env
HTTP_EXTERNAL_PORT=8081
HTTPS_EXTERNAL_PORT=8444
```

**Production (standard ports):**
```bash
# .env  
HTTP_EXTERNAL_PORT=80
HTTPS_EXTERNAL_PORT=443
```

**Custom deployment:**
```bash
# .env
HTTP_EXTERNAL_PORT=3000
HTTPS_EXTERNAL_PORT=3443
SSH_EXTERNAL_PORT=2223
```

### DNS Configuration

For production deployment, configure DNS:
```
# A record
your-domain.com.     IN  A  YOUR_SERVER_IP

# Wildcard for subdomains  
*.your-domain.com.   IN  A  YOUR_SERVER_IP
```

## Development Setup

### Prerequisites
- Docker and Docker Compose
- No local Go installation required (everything runs in containers)

### Running Tests
```bash
# Unit tests with coverage
make test

# End-to-end tests (automatically generates SSH keys)
make e2e

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
│   ├── config/         # Configuration management
│   ├── ssh/            # SSH server implementation  
│   └── proxy/          # HTTP/HTTPS reverse proxy
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
- **For password auth**: Verify username is `tunnel` and password is `test123`
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
curl -I http://your-server.com:8080

# Test with subdomain
curl -H "Host: abc123.your-server.com" http://your-server.com:8080
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
netstat -tlnp | grep :8080

# Check logs for specific errors
docker compose logs ssh-tunnel
```

## Security Considerations

### Development vs Production

**Development (current):**
- Password authentication (`tunnel`/`test123`)
- HTTP only (no HTTPS)
- Self-signed certificates
- Localhost domain

**Production (recommended):**
- SSH key authentication only
- HTTPS with Let's Encrypt certificates
- Real domain names
- Rate limiting and monitoring

### Best Practices

1. **Use SSH keys** instead of passwords in production
2. **Configure firewall** to limit SSH access
3. **Monitor tunnel usage** and implement rate limiting
4. **Regular updates** and security patches
5. **Backup certificate data** for HTTPS

## Limitations

### Current Limitations
- No tunnel management interface
- No connection rate limiting  
- Basic monitoring only

### Completed Features
- ✅ SSH tunnel creation and HTTP proxy routing
- ✅ HTTPS with automatic Let's Encrypt certificates
- ✅ Self-signed certificate generation for development
- ✅ SSH key authentication
- ✅ Custom ACME server support (for internal PKI)
- ✅ **Built-in ACME rate limiting** (protects against Let's Encrypt limits)
- ✅ Comprehensive configuration options

### Planned Features
- 📋 Web-based tunnel management interface
- 📋 Rate limiting and security hardening
- 📋 Monitoring and usage analytics
- 📋 Multiple authentication backends
- 📋 Tunnel persistence and reconnection

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

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/bohrer-go/issues)
- **Documentation**: This README and [CLAUDE.md](CLAUDE.md)
- **Development**: See [CLAUDE.md](CLAUDE.md) for development guidelines

---

**Quick Test**: Try the tunnel server with a simple Python HTTP server:
```bash
# Terminal 1: Start a simple web server
echo "Hello from my local server!" > index.html
python -m http.server 8000

# Terminal 2: Create tunnel  
ssh -R 0:localhost:8000 tunnel@your-server.com -p 2222

# Access via provided URL to see your local file served publicly
```