# Examples

This directory contains various examples and configuration files to help you get started with the Rust Verusd RPC Server.

## Contents

### Basic Usage
- **`basic-usage.sh`** - Shell script with basic usage examples and curl commands

### Deployment Examples
- **`docker-compose.yml`** - Docker Compose configuration for containerized deployment
- **`nginx.conf`** - Nginx reverse proxy configuration with TLS termination
- **`verusd-rpc-proxy.service`** - Systemd service unit file for Linux systems

### Client Examples
- **`client-example.py`** - Python client library and usage examples
- **`client-example.js`** - JavaScript/Node.js client library and usage examples

## Quick Start

### 1. Basic Usage

The simplest way to get started:

```bash
# View the basic usage examples
bash examples/basic-usage.sh
```

### 2. Docker Deployment

Deploy using Docker Compose:

```bash
# Copy the docker-compose.yml to your deployment directory
cp examples/docker-compose.yml .

# Update the API keys and other sensitive values
vi docker-compose.yml

# Start the services
docker-compose up -d

# Check the logs
docker-compose logs -f rpc-proxy
```

### 3. Systemd Service

Install as a systemd service on Linux:

```bash
# Copy the service file
sudo cp examples/verusd-rpc-proxy.service /etc/systemd/system/

# Edit the service file with your configuration
sudo vi /etc/systemd/system/verusd-rpc-proxy.service

# Reload systemd
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable verusd-rpc-proxy
sudo systemctl start verusd-rpc-proxy

# Check status
sudo systemctl status verusd-rpc-proxy
```

### 4. Nginx Reverse Proxy

Set up Nginx as a reverse proxy with TLS:

```bash
# Copy the nginx configuration
sudo cp examples/nginx.conf /etc/nginx/nginx.conf

# Update the configuration with your domain and certificate paths
sudo vi /etc/nginx/nginx.conf

# Test the configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

### 5. Client Libraries

#### Python Client

```bash
# Install dependencies
pip install requests

# Run the example
python examples/client-example.py
```

Or use in your Python code:

```python
from client_example import VerusRPCClient

client = VerusRPCClient(
    url="http://localhost:8080",
    api_key="your-api-key"
)

info = client.get_info()
print(f"Block count: {info['blocks']}")
```

#### JavaScript/Node.js Client

```bash
# Install dependencies
npm install node-fetch

# Run the example
node examples/client-example.js
```

Or use in your Node.js code:

```javascript
const { VerusRPCClient } = require('./client-example');

const client = new VerusRPCClient(
    'http://localhost:8080',
    'your-api-key'
);

const info = await client.getInfo();
console.log(`Block count: ${info.blocks}`);
```

## Configuration Tips

### Security Best Practices

1. **Always use API keys in production**
   ```bash
   VERUS_RPC_API_KEYS="your-long-random-api-key"
   ```

2. **Use specific CORS origins (not `*`)**
   ```bash
   VERUS_RPC_CORS_ALLOWED_ORIGINS="https://your-frontend.com"
   ```

3. **Bind to localhost if not using a reverse proxy**
   ```bash
   VERUS_RPC_SERVER_ADDR="127.0.0.1"
   ```

4. **Use TLS termination with Nginx or Caddy**
   - Never expose the RPC endpoint without TLS in production

5. **Set appropriate rate limits**
   ```bash
   VERUS_RPC_RATE_LIMIT_PER_MINUTE=60
   VERUS_RPC_RATE_LIMIT_BURST=10
   ```

### Method Allowlist Presets

Choose a preset based on your security requirements:

- **`readonly`** - Only read-only methods (recommended for public APIs)
  ```bash
  VERUS_RPC_METHODS_PRESET=readonly
  ```

- **`standard`** - Read-only plus some additional safe methods
  ```bash
  VERUS_RPC_METHODS_PRESET=standard
  ```

- **`full`** - All methods (use with caution, not recommended for public APIs)
  ```bash
  VERUS_RPC_METHODS_PRESET=full
  ```

### Monitoring and Health Checks

The server provides several endpoints for monitoring:

- **`/health`** - Liveness probe (checks if server is running)
- **`/ready`** - Readiness probe (checks if server can handle requests)
- **`/metrics`** - Prometheus metrics (if enabled)

Example health check:
```bash
curl http://localhost:8080/health
# Returns: {"status":"healthy","rpc":"connected"}
```

## Troubleshooting

### Connection Issues

If you can't connect to the server:

1. Check if the server is running
2. Verify the port is not blocked by a firewall
3. Check the logs: `journalctl -u verusd-rpc-proxy -f`

### Authentication Errors

If you get 401 errors:

1. Verify your API key is correct
2. Check that you're including the API key in the request headers
3. Try using `X-API-Key` header instead of `Authorization: Bearer`

### Rate Limiting

If you hit rate limits (429 errors):

1. Reduce request frequency
2. Contact the server administrator to increase limits
3. Use caching on the client side for frequently requested data

## Additional Resources

- [Main README](../README.md) - Project overview and installation
- [Configuration Guide](../Conf.toml.example) - Detailed configuration options
- [API Documentation](../docs/) - Complete API reference
