# Rust Verusd RPC Server

A high-performance, secure RPC proxy server for Verus blockchain nodes written in Rust. This server sits between your clients and the Verus daemon, providing enhanced security, rate limiting, and request validation capabilities.

## Features

### Security
- **API Key Authentication**: Protect your RPC endpoint with multiple API keys
- **Rate Limiting**: Per-IP rate limiting to prevent DDoS attacks (60 req/min default)
- **TLS/HTTPS Support**: Encrypt traffic with SSL/TLS certificates
- **Configurable CORS**: Control which origins can access your API
- **Input Validation**: Strict parameter validation to prevent injection attacks
- **Method Allowlist**: Only approved RPC methods are forwarded

### Performance
- **Request Timeout**: Configurable timeouts to prevent hanging requests (30s default)
- **Connection Pooling**: Automatic HTTP connection reuse for upstream RPC
- **Async I/O**: Built on Tokio for maximum concurrency

### Operations
- **Health Checks**: `/health` endpoint for monitoring and load balancers
- **Structured Logging**: Request tracing with unique request IDs
- **Graceful Shutdown**: SIGTERM/SIGINT handling with connection draining
- **Environment Variables**: Full configuration via environment variables
- **Docker Support**: Production-ready Docker image with security best practices

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

# Optional: TLS/HTTPS configuration
# If both are provided, server will use HTTPS
tls_cert_path = "/path/to/cert.pem"
tls_key_path = "/path/to/key.pem"
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
export VERUS_RPC_TLS_CERT_PATH="/path/to/cert.pem"
export VERUS_RPC_TLS_KEY_PATH="/path/to/key.pem"
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

### Health Check

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

### Production Docker Deployment

For production with HTTPS:

```bash
docker run -d \
  --name verus-rpc-server \
  -p 443:8080 \
  -v /path/to/certs:/certs:ro \
  -e VERUS_RPC_RPC_URL=http://verusd:27486 \
  -e VERUS_RPC_RPC_USER=username \
  -e VERUS_RPC_RPC_PASSWORD=password \
  -e VERUS_RPC_SERVER_PORT=8080 \
  -e VERUS_RPC_SERVER_ADDR=0.0.0.0 \
  -e VERUS_RPC_API_KEYS="key1,key2,key3" \
  -e VERUS_RPC_TLS_CERT_PATH=/certs/cert.pem \
  -e VERUS_RPC_TLS_KEY_PATH=/certs/key.pem \
  -e VERUS_RPC_CORS_ALLOWED_ORIGINS="https://yourdomain.com" \
  --restart unless-stopped \
  rust_verusd_rpc_server
```

## Security Best Practices

### Production Checklist

- [ ] **Enable API Key Authentication**: Set `api_keys` with strong, random keys
- [ ] **Enable TLS/HTTPS**: Provide valid certificate and key files
- [ ] **Configure CORS**: Specify exact allowed origins (not `"*"`)
- [ ] **Adjust Rate Limits**: Set appropriate limits for your use case
- [ ] **Use Environment Variables**: Don't commit `Conf.toml` with secrets
- [ ] **Run as Non-Root**: The Docker image uses a non-root user by default
- [ ] **Monitor Logs**: Set up log aggregation for security monitoring
- [ ] **Keep Updated**: Regularly update to get security patches

### Generating TLS Certificates

For testing, generate self-signed certificates:

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

For production, use [Let's Encrypt](https://letsencrypt.org/) or your certificate provider.

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

Set up monitoring on the `/health` endpoint:

```bash
# Returns 200 OK if healthy
curl -f http://localhost:8080/health || echo "Server unhealthy"
```

Integrate with monitoring tools like:
- Prometheus + Grafana
- Datadog
- New Relic
- AWS CloudWatch

## Allowed RPC Methods

The server implements a strict allowlist for security. Only these methods are allowed:

**Blockchain Info:**
- `getinfo`, `getblockchaininfo`, `getnetworkinfo`, `getmininginfo`
- `getblock`, `getblockcount`, `getblockhash`, `getblockheader`, `getbestblockhash`
- `getchaintips`, `getdifficulty`, `getblocksubsidy`

**Transactions:**
- `getrawtransaction`, `decoderawtransaction`, `sendrawtransaction`
- `createrawtransaction`, `decodescript`, `gettxout`, `gettxoutsetinfo`

**Addresses:**
- `getaddressbalance`, `getaddressdeltas`, `getaddressmempool`
- `getaddresstxids`, `getaddressutxos`, `getspentinfo`

**Identity & Currency:**
- `getidentity`, `getcurrency`, `getcurrencystate`, `getcurrencyconverters`
- `getidentitycontent`, `listcurrencies`, `getoffers`

**Utilities:**
- `help`, `coinsupply`, `estimatefee`, `estimatepriority`
- `verifymessage`, `verifyhash`, `verifysignature`

And more... See `src/allowlist.rs` for the complete list.

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

### TLS/Certificate errors

**Verify certificate files:**
```bash
# Check certificate validity
openssl x509 -in cert.pem -text -noout

# Check private key
openssl rsa -in key.pem -check
```

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
