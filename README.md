# Rust Verusd RPC Server

A high-performance, secure RPC proxy server for Verus blockchain nodes written in Rust. This server sits between your clients and the Verus daemon, providing enhanced security, rate limiting, and request validation capabilities.

## Features

### Security
- **API Key Authentication**: Protect your RPC endpoint with multiple API keys
- **Advanced Rate Limiting**: Per-IP global + per-method rate limiting with configurable limits
- **IP Access Control**: Allowlist/blocklist with CIDR notation support
- **Reverse Proxy Ready**: Designed to work behind Caddy/nginx for HTTPS termination
- **Configurable CORS**: Control which origins can access your API
- **Input Validation**: Strict parameter validation to prevent injection attacks
- **Method Allowlist**: Only approved RPC methods are forwarded
- **Audit Logging**: Comprehensive security event logging for compliance

### Performance
- **Request Timeout**: Configurable timeouts to prevent hanging requests (30s default)
- **Connection Pooling**: Automatic HTTP connection reuse for upstream RPC
- **Async I/O**: Built on Tokio for maximum concurrency
- **Response Caching**: LRU cache with TTL for frequently requested data

### Operations
- **Health Checks**: `/health` endpoint for liveness probes
- **Readiness Checks**: `/ready` endpoint for Kubernetes readiness probes
- **Prometheus Metrics**: `/metrics` endpoint with comprehensive observability
- **Docker Health Monitoring**: Built-in HEALTHCHECK directive
- **Structured Logging**: Request tracing with unique request IDs
- **Audit Logging**: Configurable security event logging
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

# Optional: Prometheus metrics
[metrics]
enabled = true          # Enable metrics collection (default: true)
endpoint = "/metrics"   # Metrics endpoint path (default: "/metrics")

# Optional: Per-method rate limiting
[method_rate_limits]
default = 60  # Default limit for all methods (requests/minute)

# Per-method limits (override default)
[method_rate_limits.methods]
getblock = 10            # Expensive operations get lower limits
getrawtransaction = 20
getaddressbalance = 30

# Optional: IP access control (allowlist/blocklist)
[ip_access]
# Allowlist: If not empty, ONLY these IPs/networks are allowed
allowlist = [
    "192.168.1.0/24",    # Local network
    "10.0.0.0/8",        # Private network
    "203.0.113.5/32"     # Specific IP
]

# Blocklist: Always denied, even if in allowlist
blocklist = [
    "192.168.1.100/32",  # Blocked specific IP
    "198.51.100.0/24"    # Blocked network
]

# Optional: Audit logging for security events
[audit]
enabled = true              # Enable audit logging (default: false)
log_requests = true         # Log all RPC requests (can be verbose)
log_responses = false       # Log response bodies (can be very large)
log_errors = true           # Log errors (recommended)
log_auth = true             # Log authentication attempts
log_rate_limits = true      # Log rate limit hits

# Optional: Response caching
[cache]
enabled = true              # Enable response caching (default: false)
ttl_seconds = 10            # Default TTL for cached responses
max_entries = 1000          # Maximum cache entries (LRU eviction)

# Methods to cache (only idempotent read operations)
methods = [
    "getinfo",
    "getblockcount",
    "getdifficulty",
    "getbestblockhash"
]

# Per-method TTL overrides (in seconds)
[cache.method_ttl]
getinfo = 5                 # Cache for 5 seconds
getblockcount = 2           # Cache for 2 seconds
getdifficulty = 30          # Cache for 30 seconds

# Optional: Upstream connection configuration
[upstream]
max_connections = 100       # Maximum concurrent connections
connection_timeout_ms = 5000    # Connection timeout
keep_alive_timeout_ms = 90000   # Keep-alive timeout

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

## Prometheus Metrics

The server exposes Prometheus-compatible metrics at the `/metrics` endpoint for comprehensive observability.

### Available Metrics

**HTTP Metrics:**
- `http_requests_total` - Total HTTP requests by endpoint, method, and status code
- `http_request_duration_seconds` - HTTP request latency histogram
- `active_connections` - Current number of active connections

**RPC Metrics:**
- `rpc_calls_total` - Total RPC calls by method and status
- `rpc_call_duration_seconds` - RPC call latency histogram by method

**Rate Limiting:**
- `rate_limit_hits_total` - Rate limit violations by IP and limit type

**Authentication:**
- `auth_attempts_total` - Authentication attempts by status (success/failure)
- `method_rejections_total` - Method allowlist rejections by method

**Errors:**
- `errors_total` - Errors by type and method
- `upstream_errors_total` - Upstream RPC errors by error code

**Caching (when enabled):**
- `cache_operations_total` - Cache operations (hit/miss/expired) by method
- `cache_size` - Current number of cache entries

**System:**
- `uptime_seconds` - Server uptime in seconds
- `request_size_bytes_total` - Total bytes received in requests
- `response_size_bytes_total` - Total bytes sent in responses

### Configuration

```toml
[metrics]
enabled = true          # Enable metrics (default: true)
endpoint = "/metrics"   # Endpoint path (default: "/metrics")
```

### Accessing Metrics

```bash
# Fetch metrics
curl http://localhost:8080/metrics

# Example output:
# http_requests_total{endpoint="/",method="POST",status="200"} 1523
# rpc_calls_total{method="getinfo",status="success"} 1245
# rpc_call_duration_seconds_bucket{method="getblock",le="0.1"} 892
```

### Prometheus Configuration

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'verus_rpc'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Grafana Dashboard

Create custom dashboards to visualize:
- Request rate and latency percentiles
- Error rates by method
- Rate limit violations
- Cache hit rates
- Active connections over time

## Advanced Rate Limiting

The server implements hierarchical rate limiting with both global per-IP limits and per-method limits.

### How It Works

1. **Global Limit** (always checked first):
   - Applied per IP address
   - Prevents individual IPs from overwhelming the server
   - Default: 60 requests/minute with burst of 10

2. **Per-Method Limits** (checked second):
   - Applied per IP per method
   - Allows fine-grained control for expensive operations
   - Only active for methods explicitly configured

3. **Hierarchical Enforcement**:
   - Global limit checked first
   - If passed, method-specific limit checked (if configured)
   - Request rejected if either limit is exceeded

### Configuration

```toml
# Global limits (per IP)
rate_limit_per_minute = 60   # Base rate
rate_limit_burst = 10         # Burst capacity

# Per-method limits
[method_rate_limits]
default = 60  # Fallback for methods without specific limits

[method_rate_limits.methods]
getblock = 10                 # Heavy operation
getrawtransaction = 20
getaddressbalance = 30
getaddressutxos = 30
```

### Example Scenarios

**Scenario 1: Normal usage**
- Client makes 5 `getinfo` requests/minute → ✅ Allowed (under global limit)

**Scenario 2: Method-specific limit**
- Client makes 15 `getblock` requests/minute → ❌ Blocked (exceeds method limit of 10)
- But can still make other requests (global limit not exceeded)

**Scenario 3: Global limit**
- Client makes 65 total requests/minute → ❌ Blocked (exceeds global limit)
- Even if each method is under its specific limit

### Rate Limit Response

When rate limited, clients receive:

```json
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "error": {
    "code": -32005,
    "message": "Rate limit exceeded. Please try again later.",
    "request_id": "uuid-here"
  }
}
```

### Monitoring

Track rate limit hits via Prometheus metrics:
```
rate_limit_hits_total{ip="192.168.1.100",limit_type="global"} 5
rate_limit_hits_total{ip="192.168.1.100",limit_type="method_getblock"} 3
```

## IP Access Control

Fine-grained IP-based access control using CIDR notation for allowlisting and blocklisting.

### Configuration

```toml
[ip_access]
# Allowlist: If not empty, ONLY these IPs/networks can access
allowlist = [
    "192.168.1.0/24",      # Local network
    "10.0.0.0/8",          # Private network
    "203.0.113.5/32",      # Specific IP
    "2001:db8::/32"        # IPv6 network
]

# Blocklist: Always denied, even if in allowlist
blocklist = [
    "192.168.1.100/32",    # Blocked IP within allowed network
    "198.51.100.0/24"      # Blocked network
]
```

### Logic

1. **Blocklist takes precedence** - IPs in blocklist are always denied
2. **Empty allowlist = allow all** - If allowlist is empty, all IPs allowed (except blocked)
3. **Non-empty allowlist = deny by default** - If allowlist has entries, only those IPs allowed
4. **CIDR notation** - Use `/32` for single IPs, `/24` for networks, etc.

### Use Cases

**Public endpoint with exceptions:**
```toml
[ip_access]
# Allow everyone
allowlist = []
# Block known bad actors
blocklist = ["198.51.100.0/24"]
```

**Private network only:**
```toml
[ip_access]
# Only local networks
allowlist = ["192.168.0.0/16", "10.0.0.0/8"]
blocklist = []
```

**Allow specific IPs, block one:**
```toml
[ip_access]
# Allow office network
allowlist = ["203.0.113.0/24"]
# Block one problematic IP
blocklist = ["203.0.113.50/32"]
```

### Health Endpoints Exempt

The `/health`, `/ready`, and `/metrics` endpoints bypass IP filtering for monitoring.

### Denial Response

```json
HTTP/1.1 403 Forbidden

{
  "error": {
    "code": -32002,
    "message": "Access denied: IP 198.51.100.5 is in blocklist",
    "request_id": "uuid-here"
  }
}
```

## Audit Logging

Comprehensive security event logging for compliance and forensics.

### Configuration

```toml
[audit]
enabled = true              # Master switch (default: false)
log_requests = true         # Log all RPC requests (verbose)
log_responses = false       # Log response bodies (very verbose)
log_errors = true           # Log errors (recommended)
log_auth = true             # Log authentication attempts
log_rate_limits = true      # Log rate limit violations
```

### Log Format

All audit logs use structured logging with consistent fields:

```json
{
  "level": "warn",
  "timestamp": "2025-10-27T19:45:23.123Z",
  "target": "audit",
  "event_type": "authentication",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "client_ip": "192.168.1.100",
  "success": false,
  "reason": "invalid_key",
  "message": "Authentication failed"
}
```

### Event Types

**Authentication Events:**
```
event_type = "authentication"
- Logs all auth attempts (success/failure)
- Includes key name (if successful) or failure reason
```

**Rate Limit Events:**
```
event_type = "rate_limit"
- Logs when clients hit rate limits
- Includes IP and limit type (global or method-specific)
```

**Error Events:**
```
event_type = "error"
- Logs RPC errors
- Includes error type, code, method, and message
```

**Method Rejection Events:**
```
event_type = "method_rejection"
- Logs when methods are blocked by allowlist
- Includes method name and rejection reason
```

**Request/Response Events (verbose):**
```
event_type = "rpc_request" | "rpc_response"
- Logs full request/response details
- Can be very verbose, use sparingly
```

### Use Cases

**Compliance:**
```toml
[audit]
enabled = true
log_requests = true      # Track all API usage
log_responses = false    # Avoid logging sensitive data
log_errors = true
log_auth = true          # Track who accessed what
log_rate_limits = true
```

**Debugging:**
```toml
[audit]
enabled = true
log_requests = true
log_responses = true     # Full request/response logging
log_errors = true
log_auth = true
log_rate_limits = true
```

**Security monitoring:**
```toml
[audit]
enabled = true
log_requests = false     # Reduce noise
log_responses = false
log_errors = true
log_auth = true          # Track suspicious activity
log_rate_limits = true   # Track abuse attempts
```

### Log Aggregation

Integrate with:
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk**
- **Datadog**
- **CloudWatch Logs**
- **Grafana Loki**

All audit logs include `request_id` for correlation.

## Response Caching

LRU (Least Recently Used) cache with TTL for frequently requested data.

### Configuration

```toml
[cache]
enabled = true              # Enable caching
ttl_seconds = 10            # Default TTL
max_entries = 1000          # Max cache size (LRU eviction)

# Only cache safe, idempotent operations
methods = [
    "getinfo",
    "getblockcount",
    "getdifficulty",
    "getbestblockhash"
]

# Per-method TTL overrides
[cache.method_ttl]
getinfo = 5                 # Short TTL for rapidly changing data
getblockcount = 2
getdifficulty = 30          # Longer TTL for stable data
```

### How It Works

1. **Cache Key**: `method:params` (exact match required)
2. **TTL Expiration**: Entries auto-expire after configured TTL
3. **LRU Eviction**: When full, least recently used entries evicted
4. **Thread-Safe**: Lock-free reads, efficient writes

### Cache Behavior

**Cache Hit:**
```
Client → Server: getinfo request
Server: Cache HIT (returns cached response in <1ms)
```

**Cache Miss:**
```
Client → Server: getinfo request
Server: Cache MISS → Forward to verusd → Cache response → Return
```

**Cache Expired:**
```
Client → Server: getinfo request
Server: Cache HIT but expired → Forward to verusd → Update cache → Return
```

### Best Practices

**✅ Good to cache:**
- `getinfo` (network info)
- `getblockcount` (chain height)
- `getdifficulty` (network difficulty)
- `getbestblockhash` (latest block hash)
- `getblockchaininfo` (blockchain state)

**❌ Don't cache:**
- `sendrawtransaction` (state-changing)
- `getrawmempool` (rapidly changing)
- `getaddressbalance` (user-specific, privacy)
- Any method with user-specific data

**TTL Guidelines:**
- **1-5s**: Rapidly changing data (mempool, recent blocks)
- **10-30s**: Moderate change rate (difficulty, network info)
- **60s+**: Stable data (old blocks, historical data)

### Monitoring

Track cache performance via Prometheus:
```
cache_operations_total{operation="hit",method="getinfo"} 8923
cache_operations_total{operation="miss",method="getinfo"} 123
cache_operations_total{operation="expired",method="getinfo"} 45
cache_size 847
```

**Hit Rate Calculation:**
```
hit_rate = hits / (hits + misses)
```

### Example Configuration

**High-traffic public endpoint:**
```toml
[cache]
enabled = true
ttl_seconds = 5
max_entries = 10000
methods = ["getinfo", "getblockcount", "getdifficulty", "getbestblockhash"]

[cache.method_ttl]
getinfo = 2
getblockcount = 1
```

**Internal service:**
```toml
[cache]
enabled = false  # Disable for internal services that need real-time data
```

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

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Issues: [GitHub Issues](https://github.com/devdudeio/rust_verusd_rpc_server/issues)
- Discussions: [GitHub Discussions](https://github.com/devdudeio/rust_verusd_rpc_server/discussions)

## Acknowledgments

Built for the Verus community with ❤️
