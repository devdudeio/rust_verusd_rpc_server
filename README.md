# Rust Verusd RPC Server

A high-performance, secure RPC proxy server for Verus blockchain nodes written in Rust. This server sits between your clients and the Verus daemon, providing enhanced security, rate limiting, and request validation capabilities.

## Features

### Security
- **API Key Authentication**: Protect your RPC endpoint with multiple API keys
- **Rate Limiting**: Per-IP rate limiting to prevent DDoS attacks (60 req/min default)
- **Reverse Proxy Ready**: Designed to work behind Caddy/nginx for HTTPS termination
- **Configurable CORS**: Control which origins can access your API
- **Input Validation**: Strict parameter validation to prevent injection attacks
- **Method Allowlist**: Only approved RPC methods are forwarded

### Performance
- **Request Timeout**: Configurable timeouts to prevent hanging requests (30s default)
- **Connection Pooling**: Automatic HTTP connection reuse for upstream RPC
- **Async I/O**: Built on Tokio for maximum concurrency

### Operations
- **Health Checks**: `/health` endpoint for liveness probes
- **Readiness Checks**: `/ready` endpoint for Kubernetes readiness probes
- **Docker Health Monitoring**: Built-in HEALTHCHECK directive
- **Structured Logging**: Request tracing with unique request IDs
- **Graceful Shutdown**: SIGTERM/SIGINT handling with connection draining
- **Environment Variables**: Full configuration via environment variables
- **Docker Support**: Production-ready Docker image with security best practices
- **Security Validation**: Automatic configuration security checks on startup

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Pull the latest image
docker pull ghcr.io/devdudeio/rust_verusd_rpc_server:latest

# Run with minimal config
docker run -d \
  -p 8080:8080 \
  -e VERUS_RPC_RPC_URL=http://localhost:27486 \
  -e VERUS_RPC_RPC_USER=yourusername \
  -e VERUS_RPC_RPC_PASSWORD=yourpassword \
  -e VERUS_RPC_SERVER_PORT=8080 \
  -e VERUS_RPC_SERVER_ADDR=0.0.0.0 \
  rust_verusd_rpc_server
```

### Option 2: Build from Source

**Prerequisites:**
- Rust 1.70+ ([Install Rust](https://www.rust-lang.org/tools/install))
- Git

```bash
# Clone the repository
git clone https://github.com/devdudeio/rust_verusd_rpc_server.git
cd rust_verusd_rpc_server

# Create configuration file
cp Conf.toml.example Conf.toml

# Edit Conf.toml with your settings
nano Conf.toml

# Build and run
cargo build --release
./target/release/rust_verusd_rpc_server
```

## Configuration

### Configuration File (Conf.toml)

Create a `Conf.toml` file in the project root:

```toml
# Required: Upstream Verus RPC connection
rpc_url = "http://localhost:27486"
rpc_user = "yourusername"
rpc_password = "yourpassword"

# Required: Server binding
server_port = 8080
server_addr = "0.0.0.0"

# Optional: Request timeout in seconds (default: 30)
request_timeout = 30

# Optional: Rate limiting per IP
rate_limit_per_minute = 60  # Max requests per IP per minute
rate_limit_burst = 10        # Burst capacity

# Optional: API key authentication
# Comma-separated list of valid API keys
# If not set, authentication is disabled (not recommended for production!)
api_keys = "secret-key-1,secret-key-2,secret-key-3"

# Optional: CORS configuration
# Comma-separated list of allowed origins (default: "*")
# For production, specify exact origins
cors_allowed_origins = "https://example.com,https://app.example.com"

# Optional: Method allowlist configuration
# Controls which RPC methods are allowed to be called
[methods]
# Preset mode: "minimal" | "safe" | "full" | "custom" (default: "safe")
# - minimal: Only basic info methods (getinfo, getblockcount, etc.)
# - safe: All read-only methods, no spending/wallet operations
# - full: All methods in the allowlist including identity operations
# - custom: Define your own using allow_groups, allow_extra, and deny
preset = "safe"

# When preset = "custom", specify which method groups to allow:
# Available groups: readonly, blockchain, mempool, address, currency,
#                   identity, verification, rawtx, utility, advanced
# allow_groups = ["readonly", "blockchain", "currency"]

# When preset = "custom", add specific methods not in groups:
# allow_extra = ["sendcurrency"]

# When preset = "custom", deny specific methods (takes precedence):
# deny = ["fundrawtransaction"]

# Note: For HTTPS, use Caddy or nginx as a reverse proxy
# See the "HTTPS with Caddy" section below
```

### Environment Variables

All configuration options can be set via environment variables with the `VERUS_RPC_` prefix:

```bash
# Required
export VERUS_RPC_RPC_URL="http://localhost:27486"
export VERUS_RPC_RPC_USER="username"
export VERUS_RPC_RPC_PASSWORD="password"
export VERUS_RPC_SERVER_PORT="8080"
export VERUS_RPC_SERVER_ADDR="0.0.0.0"

# Optional
export VERUS_RPC_REQUEST_TIMEOUT="30"
export VERUS_RPC_RATE_LIMIT_PER_MINUTE="60"
export VERUS_RPC_RATE_LIMIT_BURST="10"
export VERUS_RPC_API_KEYS="key1,key2,key3"
export VERUS_RPC_CORS_ALLOWED_ORIGINS="https://example.com"
```

**Note:** Environment variables override values in `Conf.toml`.

## Usage Examples

### Basic RPC Request

```bash
# Without authentication
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{
    "method": "getinfo",
    "params": []
  }'
```

### With API Key Authentication

```bash
# Using X-API-Key header
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-secret-key" \
  -d '{
    "method": "getblockcount",
    "params": []
  }'

# Using Authorization Bearer token
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-secret-key" \
  -d '{
    "method": "getblockcount",
    "params": []
  }'
```

### Health Check (Liveness)

```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "status": "healthy",
  "rpc": "connected"
}
```

### Readiness Check

The `/ready` endpoint is designed for Kubernetes readiness probes. It returns 200 when ready, 503 when not ready:

```bash
curl http://localhost:8080/ready
```

**Response (ready):**
```json
{
  "status": "ready",
  "rpc": "ready"
}
```

**Response (not ready) - HTTP 503:**
```json
{
  "status": "not_ready",
  "rpc": "not_ready",
  "error": "RPC timeout"
}
```

### JavaScript/Node.js Example

```javascript
const response = await fetch('http://localhost:8080', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'your-secret-key'
  },
  body: JSON.stringify({
    method: 'getinfo',
    params: []
  })
});

const data = await response.json();
console.log(data.result);
```

## Docker Deployment

### Building the Docker Image

```bash
docker build -t rust_verusd_rpc_server .
```

### Running with Docker Compose

Create a `docker-compose.yml`:

```yaml
version: '3.8'

services:
  rpc-server:
    image: rust_verusd_rpc_server
    ports:
      - "8080:8080"
    environment:
      VERUS_RPC_RPC_URL: "http://verusd:27486"
      VERUS_RPC_RPC_USER: "username"
      VERUS_RPC_RPC_PASSWORD: "password"
      VERUS_RPC_SERVER_PORT: "8080"
      VERUS_RPC_SERVER_ADDR: "0.0.0.0"
      VERUS_RPC_API_KEYS: "your-secret-key"
      VERUS_RPC_RATE_LIMIT_PER_MINUTE: "100"
      VERUS_RPC_CORS_ALLOWED_ORIGINS: "https://yourdomain.com"
    restart: unless-stopped
    networks:
      - verus-network

networks:
  verus-network:
    driver: bridge
```

Run with:
```bash
docker-compose up -d
```

## HTTPS with Caddy

For production deployments, use [Caddy](https://caddyserver.com/) as a reverse proxy to handle HTTPS. Caddy automatically obtains and renews Let's Encrypt certificates.

### Installing Caddy

```bash
# Ubuntu/Debian
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install caddy
```

### Configure Caddy

Create or edit `/etc/caddy/Caddyfile`:

```caddyfile
# Replace with your domain
your-domain.com {
    # Automatic HTTPS with Let's Encrypt

    # Reverse proxy to Rust RPC server
    reverse_proxy localhost:8080 {
        # Health check
        health_uri /health
        health_interval 10s
        health_timeout 5s

        # Forward real IP
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }

    # Additional security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        -Server
    }

    # Logging
    log {
        output file /var/log/caddy/verus-rpc.log
        format json
    }
}
```

### Start Caddy

```bash
# Reload Caddy configuration
sudo systemctl reload caddy

# Check status
sudo systemctl status caddy

# View logs
sudo journalctl -u caddy -f
```

### Docker Compose with Caddy

Create a complete `docker-compose.yml`:

```yaml
version: '3.8'

services:
  rpc-server:
    image: rust_verusd_rpc_server
    expose:
      - "8080"
    environment:
      VERUS_RPC_RPC_URL: "http://verusd:27486"
      VERUS_RPC_RPC_USER: "username"
      VERUS_RPC_RPC_PASSWORD: "password"
      VERUS_RPC_SERVER_PORT: "8080"
      VERUS_RPC_SERVER_ADDR: "0.0.0.0"
      VERUS_RPC_API_KEYS: "your-secret-key"
      VERUS_RPC_CORS_ALLOWED_ORIGINS: "https://yourdomain.com"
    restart: unless-stopped
    networks:
      - verus-network

  caddy:
    image: caddy:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    restart: unless-stopped
    networks:
      - verus-network

networks:
  verus-network:
    driver: bridge

volumes:
  caddy_data:
  caddy_config:
```

## Security Best Practices

### Automatic Security Validation

The server performs automatic security checks on startup and warns about:
- Default or common RPC credentials (testuser, testpassword, etc.)
- Weak RPC passwords (less than 12 characters)
- Weak API keys (less than 16 characters or simple patterns)
- Public binding (0.0.0.0) without authentication
- Wildcard CORS configuration (*)

These warnings help identify misconfigurations before deployment.

### Production Checklist

- [ ] **Enable API Key Authentication**: Set `api_keys` with strong, random keys
- [ ] **Use Strong Credentials**: RPC password 12+ chars, API keys 16+ chars
- [ ] **Deploy Behind Caddy/nginx**: Use reverse proxy for HTTPS with automatic certificates
- [ ] **Configure CORS**: Specify exact allowed origins (not `"*"`)
- [ ] **Adjust Rate Limits**: Set appropriate limits for your use case
- [ ] **Use Environment Variables**: Don't commit `Conf.toml` with secrets
- [ ] **Run as Non-Root**: The Docker image uses a non-root user by default
- [ ] **Monitor Logs**: Set up log aggregation for security monitoring
- [ ] **Keep Updated**: Regularly update to get security patches
- [ ] **Configure Firewall**: Only expose Caddy (port 80/443), keep RPC server internal
- [ ] **Review Security Warnings**: Address all startup security warnings

### API Key Management

Generate secure random API keys:

```bash
# Generate a secure random key
openssl rand -hex 32

# Or using uuidgen
uuidgen
```

Rotate API keys regularly and revoke compromised keys immediately.

## Monitoring and Logging

### Log Levels

Control logging verbosity with the `RUST_LOG` environment variable:

```bash
# Error only
export RUST_LOG=error

# Info (default)
export RUST_LOG=info

# Debug (verbose)
export RUST_LOG=debug

# Trace (very verbose)
export RUST_LOG=trace
```

### Request Tracing

Every request gets a unique `X-Request-ID` header for correlation:

```bash
curl -v http://localhost:8080/health
# Look for: X-Request-ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Use this ID to trace requests through your logs.

### Health Monitoring

#### Liveness and Readiness Probes

The server provides two endpoints for health monitoring:

- `/health` - Liveness probe: Returns 200 if application is alive
- `/ready` - Readiness probe: Returns 200 if ready for traffic, 503 if not ready

```bash
# Liveness check - is the app alive?
curl -f http://localhost:8080/health || echo "Server unhealthy"

# Readiness check - is the app ready for traffic?
curl -f http://localhost:8080/ready || echo "Server not ready"
```

#### Docker Health Checks

The Docker image includes built-in health checks:

```bash
# Check container health status
docker ps

# View health check logs
docker inspect --format='{{json .State.Health}}' container_name | jq
```

#### Kubernetes Health Probes

Example Kubernetes deployment with health probes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: verus-rpc
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: verus-rpc
        image: ghcr.io/devdudeio/rust_verusd_rpc_server:latest
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
```

#### Monitoring Tools Integration

Integrate with monitoring tools like:
- Prometheus + Grafana
- Datadog
- New Relic
- AWS CloudWatch

## Method Allowlist Configuration

The server implements a configurable allowlist for security. You can control which RPC methods are allowed using **presets** or **custom groups**.

### Preset Modes

Choose a preset that matches your security requirements:

#### 1. **Minimal** (Most Restrictive)
Only basic blockchain info methods:
- `getinfo`, `getblockcount`, `getbestblockhash`, `getdifficulty`
- `getblockchaininfo`, `getnetworkinfo`, `getmininginfo`
- `gettxoutsetinfo`, `coinsupply`, `help`

**Use case:** Public endpoints, minimal exposure

#### 2. **Safe** (Default, Recommended)
All read-only methods, no spending or wallet operations:
- All **Minimal** methods
- Block/transaction queries (getblock, getrawtransaction, etc.)
- Address queries (getaddressbalance, getaddressutxos, etc.)
- Currency queries (getcurrency, getcurrencystate, etc.)
- Mempool operations (getrawmempool, getmempoolinfo, etc.)
- Signature verification (verifymessage, verifyhash, etc.)
- Utility methods (estimatefee, createmultisig, etc.)

**Use case:** Most deployments, blockchain explorers, read-only APIs

#### 3. **Full** (Least Restrictive)
All methods including identity and advanced operations:
- All **Safe** methods
- Identity operations (getidentity, registeridentity, etc.)
- Raw transaction creation (createrawtransaction, sendrawtransaction, etc.)
- Advanced operations (signdata, submitimports, etc.)

**Use case:** Trusted internal services, full functionality required

#### 4. **Custom** (Flexible)
Define your own allowlist using method groups, individual methods, and deny rules.

### Method Groups

When using `preset = "custom"`, you can combine these method groups:

- **readonly**: Basic info (getinfo, getblockcount, getdifficulty, etc.)
- **blockchain**: Block/transaction queries (getblock, getrawtransaction, etc.)
- **mempool**: Mempool operations (getrawmempool, getmempoolinfo, etc.)
- **address**: Address queries (getaddressbalance, getaddressutxos, etc.)
- **currency**: Currency operations (getcurrency, getcurrencystate, etc.)
- **identity**: Identity operations (getidentity, registeridentity, etc.)
- **verification**: Signature verification (verifymessage, verifyhash, etc.)
- **rawtx**: Raw transaction operations (createrawtransaction, sendrawtransaction, etc.)
- **utility**: Utility methods (help, estimatefee, createmultisig, etc.)
- **advanced**: Advanced operations (signdata, submitimports, etc.)

### Configuration Examples

**Example 1: Use Safe preset (default)**
```toml
[methods]
preset = "safe"
```

**Example 2: Minimal exposure for public endpoint**
```toml
[methods]
preset = "minimal"
```

**Example 3: Custom - blockchain queries + currency info only**
```toml
[methods]
preset = "custom"
allow_groups = ["readonly", "blockchain", "currency"]
```

**Example 4: Custom - safe methods + one specific advanced method**
```toml
[methods]
preset = "custom"
allow_groups = ["readonly", "blockchain", "mempool", "address", "currency"]
allow_extra = ["signdata"]
```

**Example 5: Custom - full access except specific methods**
```toml
[methods]
preset = "custom"
allow_groups = ["readonly", "blockchain", "mempool", "address", "currency", "identity", "rawtx", "utility", "advanced"]
deny = ["fundrawtransaction", "sendcurrency"]
```

### Method Validation

Beyond allowlisting, the server validates:
- **Parameter types**: Ensures params match expected types (string, number, array, object, boolean)
- **Parameter counts**: Enforces exact parameter counts where required
- **Special rules**: Custom validation for specific methods (e.g., signdata must not include address parameter)
- **Security constraints**: String length limits, array size limits, numeric ranges

For the complete list of methods and validation rules, see `src/allowlist.rs` and `src/allowlist_config.rs`.

## Troubleshooting

### Server won't start

**Check configuration:**
```bash
# Verify Conf.toml exists and is valid
cat Conf.toml

# Check environment variables
env | grep VERUS_RPC
```

**Common issues:**
- Invalid port number (must be 1-65535)
- Invalid IP address format
- Missing required configuration
- Port already in use

### Connection refused

**Verify RPC URL is correct:**
```bash
# Test direct connection to Verus daemon
curl -u username:password -X POST http://localhost:27486 \
  -d '{"method":"getinfo","params":[]}'
```

### Rate limiting

If you see `429 Too Many Requests`:
- Increase `rate_limit_per_minute` in configuration
- Check if legitimate traffic is being rate limited
- Consider implementing per-API-key rate limits

### HTTPS/Certificate issues

If using Caddy:
- Check Caddy logs: `sudo journalctl -u caddy -f`
- Verify domain DNS points to your server
- Ensure ports 80 and 443 are open
- Check Caddy configuration: `caddy validate --config /etc/caddy/Caddyfile`

### High memory usage

- Check for connection leaks
- Monitor with: `docker stats` or system tools
- Adjust rate limiting settings if needed

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Security audit
cargo audit
```

### CI/CD

The project uses GitHub Actions for:
- Automated testing on push/PR
- Code formatting checks
- Clippy linting
- Security audits
- Release builds

## Performance Tuning

### Connection Pool Size

The underlying HTTP client uses connection pooling automatically. For high-traffic scenarios:

- Increase system file descriptor limit
- Monitor connection metrics
- Consider deploying multiple instances behind a load balancer

### Rate Limiting

Adjust based on your infrastructure:

```toml
# High traffic
rate_limit_per_minute = 1000
rate_limit_burst = 100

# Low traffic / restrictive
rate_limit_per_minute = 10
rate_limit_burst = 5
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure `cargo test`, `cargo fmt`, and `cargo clippy` pass
6. Submit a pull request

## License

[Add your license here]

## Support

- Issues: [GitHub Issues](https://github.com/devdudeio/rust_verusd_rpc_server/issues)
- Discussions: [GitHub Discussions](https://github.com/devdudeio/rust_verusd_rpc_server/discussions)

## Acknowledgments

Built for the Verus community with ❤️
