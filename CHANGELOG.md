# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive integration tests with wiremock for testing RPC mocking
- Security configuration validation on startup
  - Validates RPC credentials for common/default values
  - Checks API key strength (minimum 16 characters)
  - Warns about insecure configurations (public binding without auth, etc.)
- `/ready` endpoint for Kubernetes readiness probes (separate from `/health`)
- Security warnings with visual indicators for misconfigurations

### Changed
- Replaced built-in TLS with Caddy reverse proxy architecture
  - Removed tokio-rustls and rustls-pemfile dependencies
  - Simplified server to HTTP-only
  - Added comprehensive Caddy configuration and documentation
- Improved documentation with detailed module-level rustdoc comments

### Fixed
- None

### Security
- Added timing-attack protection for API key comparison
- Enhanced input validation for all configuration parameters

## [0.1.0] - 2025-01-XX

### Added
- Initial release of Rust Verusd RPC Server
- JSON-RPC proxy server for Verus blockchain nodes
- API key authentication (X-API-Key and Bearer token support)
- Per-IP rate limiting with token bucket algorithm
- Method allowlist with parameter validation
- CORS configuration support
- Health check endpoint (`/health`)
- Request tracing with unique request IDs
- Graceful shutdown handling (SIGTERM/SIGINT)
- Docker support with security best practices
- Comprehensive README with deployment examples

### Security
- Input validation to prevent injection attacks
- Content-Type validation
- Payload size limits (50 MiB)
- Configurable CORS origins
- Security headers (HSTS, X-Frame-Options, etc.)

[Unreleased]: https://github.com/devdudeio/rust_verusd_rpc_server/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/devdudeio/rust_verusd_rpc_server/releases/tag/v0.1.0
