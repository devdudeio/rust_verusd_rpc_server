# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Prometheus Metrics** (`/metrics` endpoint)
  - HTTP request/response metrics (total, duration, size)
  - RPC call metrics (total, duration by method)
  - Rate limiting metrics (hits by IP and limit type)
  - Authentication metrics (attempts, successes, failures)
  - Error metrics (by type and method)
  - Cache metrics (hits, misses, size)
  - System metrics (uptime, active connections)
  - Full Prometheus integration with configurable endpoint
- **Advanced Rate Limiting**
  - Per-IP global rate limiting (60 req/min default with burst)
  - Per-method rate limiting (configurable limits per RPC method)
  - Hierarchical enforcement (global + method-specific)
  - Method-specific burst capacities
  - Configuration via `[method_rate_limits]` section
  - Comprehensive metrics for rate limit monitoring
- **IP Access Control**
  - Allowlist/blocklist with CIDR notation support
  - IPv4 and IPv6 network matching
  - Blocklist precedence over allowlist
  - Exempt health/metrics endpoints from filtering
  - Configuration via `[ip_access]` section
  - Detailed denial reason logging
- **Audit Logging**
  - Structured security event logging
  - Configurable log levels per event type
  - Authentication event logging
  - Rate limit violation logging
  - Error event logging
  - Method rejection logging
  - Optional request/response body logging
  - Request ID correlation for all events
  - Configuration via `[audit]` section
- **Response Caching**
  - LRU cache with TTL support
  - Per-method cache configuration
  - Per-method TTL overrides
  - Thread-safe cache operations
  - Cache hit/miss/expiration metrics
  - Configuration via `[cache]` section
- **Configurable Method Allowlist**: Complete overhaul of method allowlisting system
  - Four preset modes: `minimal`, `safe` (default), `full`, and `custom`
  - Ten method groups for flexible configuration: `readonly`, `blockchain`, `mempool`, `address`, `currency`, `identity`, `verification`, `rawtx`, `utility`, `advanced`
  - Custom mode with `allow_groups`, `allow_extra`, and `deny` options
  - Configuration via `[methods]` section in Conf.toml
  - Automatic logging of allowed method count on startup
- **Infrastructure Modules**
  - `metrics` module with lazy_static prometheus metrics
  - `config_types` module for all configuration structures
  - `rate_limit` module with governor-based rate limiting
  - `ip_filter` module with ipnetwork CIDR support
  - `audit` module with structured event logging
  - `cache` module with LRU and TTL support
  - `config` module for centralized configuration management
  - `auth` module for future per-key authorization (infrastructure ready)
- Comprehensive integration tests with wiremock for testing RPC mocking
- Security configuration validation on startup
  - Validates RPC credentials for common/default values
  - Checks API key strength (minimum 16 characters)
  - Warns about insecure configurations (public binding without auth, etc.)
- `/ready` endpoint for Kubernetes readiness probes (separate from `/health`)
- Security warnings with visual indicators for misconfigurations
- **Comprehensive Documentation**
  - Detailed README sections for all new features
  - Configuration examples for every feature
  - Best practices and use cases
  - Prometheus integration guide
  - Grafana dashboard recommendations
  - Monitoring and alerting guidance

### Changed
- Replaced built-in TLS with Caddy reverse proxy architecture
  - Removed tokio-rustls and rustls-pemfile dependencies
  - Simplified server to HTTP-only
  - Added comprehensive Caddy configuration and documentation
- **Method Allowlist Architecture**: Refactored from hardcoded list to configuration-driven
  - Created `allowlist_config` module with `MethodsConfig`, `Preset`, and `MethodGroup` types
  - Refactored `allowlist` module to use configuration-based approach
  - `VerusRPC` now holds an `Allowlist` instance instead of calling static functions
  - All existing parameter validation rules maintained
- **Rate Limiting**: Upgraded from simple global limiting to hierarchical system
  - Added per-method rate limiting on top of global limits
  - Improved burst handling with method-specific burst capacities
  - Better error messages indicating which limit was exceeded
- **Dependencies**:
  - Updated `prometheus` from 0.13 to 0.14 (fixes protobuf security vulnerability)
  - Added `lazy_static` 1.4 for metrics initialization
  - Added `parking_lot` 0.12 for efficient mutex operations
  - Added `lru` 0.12 for cache implementation
  - Added `ipnetwork` 0.20 for CIDR notation support
- Improved documentation with detailed module-level rustdoc comments
- Updated README with comprehensive feature documentation
- Enhanced Conf.toml.example with all new configuration options

### Fixed
- **Security**: Resolved RUSTSEC-2024-0437 protobuf DoS vulnerability
  - Upgraded prometheus dependency to fix transitive protobuf vulnerability
  - Protobuf updated from 2.28.0 (vulnerable) to 3.7.2 (patched)
- Clippy warnings in infrastructure code (added allow(dead_code) annotations)
- Prometheus 0.14 API compatibility (with_label_values signature change)

### Security
- Added timing-attack protection for API key comparison
- Enhanced input validation for all configuration parameters
- Improved method allowlist flexibility while maintaining strict parameter validation
- **IP-based access control** for network-level security
- **Audit logging** for security event tracking and compliance
- **Rate limiting improvements** to prevent abuse and DoS attacks
- **Metrics** for security monitoring and alerting

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
