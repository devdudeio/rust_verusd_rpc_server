#!/bin/bash
# Basic usage example for Rust Verusd RPC Server
#
# This example shows how to start the server with basic configuration
# and make RPC requests to it.

set -e

echo "=== Basic Usage Example ==="
echo ""

# 1. Start the server (assumes verusd is running locally on port 27486)
echo "Starting server with basic configuration..."
echo ""

# Create a minimal configuration file
cat > /tmp/Conf.toml <<EOF
# Basic configuration for Rust Verusd RPC Server

rpc_url = "http://127.0.0.1:27486"
rpc_user = "your_rpc_username"
rpc_password = "your_rpc_password"

server_addr = "127.0.0.1"
server_port = 8080

# Optional: Enable API key authentication (recommended)
# api_keys = "your-secret-api-key-here"

# Optional: Configure CORS (comma-separated origins)
cors_allowed_origins = "*"

# Optional: Rate limiting (requests per minute per IP)
rate_limit_per_minute = 60
rate_limit_burst = 10

[methods]
preset = "readonly"
EOF

echo "Configuration file created at /tmp/Conf.toml"
echo ""
echo "To start the server, run:"
echo "  cargo run"
echo ""
echo "Or with custom config location:"
echo "  RUST_LOG=info cargo run"
echo ""

# 2. Example RPC requests
echo "=== Example RPC Requests ==="
echo ""

echo "1. Get blockchain info:"
echo '  curl -X POST http://localhost:8080 \\'
echo '    -H "Content-Type: application/json" \\'
echo '    -d '"'"'{"method": "getinfo", "params": []}'"'"''
echo ""

echo "2. Get block count:"
echo '  curl -X POST http://localhost:8080 \\'
echo '    -H "Content-Type: application/json" \\'
echo '    -d '"'"'{"method": "getblockcount", "params": []}'"'"''
echo ""

echo "3. Get block hash (for block 1000):"
echo '  curl -X POST http://localhost:8080 \\'
echo '    -H "Content-Type: application/json" \\'
echo '    -d '"'"'{"method": "getblockhash", "params": [1000]}'"'"''
echo ""

echo "4. Health check endpoint:"
echo '  curl http://localhost:8080/health'
echo ""

echo "5. Readiness check endpoint:"
echo '  curl http://localhost:8080/ready'
echo ""

echo "=== With API Key Authentication ==="
echo ""
echo "If you enabled API keys in the configuration, include the API key in requests:"
echo ""
echo 'Using X-API-Key header:'
echo '  curl -X POST http://localhost:8080 \\'
echo '    -H "Content-Type: application/json" \\'
echo '    -H "X-API-Key: your-secret-api-key-here" \\'
echo '    -d '"'"'{"method": "getinfo", "params": []}'"'"''
echo ""

echo 'Using Authorization header:'
echo '  curl -X POST http://localhost:8080 \\'
echo '    -H "Content-Type: application/json" \\'
echo '    -H "Authorization: Bearer your-secret-api-key-here" \\'
echo '    -d '"'"'{"method": "getinfo", "params": []}'"'"''
echo ""

echo "=== Notes ==="
echo "- Health endpoint (/health) does not require authentication"
echo "- Readiness endpoint (/ready) does not require authentication"
echo "- All RPC methods require authentication if API keys are enabled"
echo "- The server forwards requests to the upstream Verus daemon"
echo "- Only allowed methods (based on preset) will be forwarded"
