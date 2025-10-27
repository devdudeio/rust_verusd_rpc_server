# Architecture

This document describes the architecture, components, and design decisions of the Rust Verusd RPC Server.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Core Components](#core-components)
- [Request Flow](#request-flow)
- [Security Model](#security-model)
- [Performance Considerations](#performance-considerations)
- [Design Decisions](#design-decisions)

## Overview

The Rust Verusd RPC Server is a high-performance, secure JSON-RPC proxy server that sits between clients and the Verus blockchain daemon. It provides enhanced security, rate limiting, caching, and monitoring capabilities while maintaining compatibility with the standard Verus RPC interface.

### Goals

1. **Security** - Protect the upstream Verus daemon from unauthorized access and abuse
2. **Performance** - Minimize latency and maximize throughput
3. **Reliability** - Handle failures gracefully with circuit breakers and health checks
4. **Observability** - Provide comprehensive logging, metrics, and audit trails

## System Architecture

```
┌─────────────┐                                    ┌──────────────┐
│   Clients   │                                    │   Verus      │
│             │                                    │   Daemon     │
│ Web Apps    │                                    │   (verusd)   │
│ Mobile Apps │                                    │              │
│ Scripts     │                                    └──────┬───────┘
└──────┬──────┘                                           │
       │                                                  │
       │ HTTPS (TLS terminated by reverse proxy)         │ HTTP
       │                                                  │
       ▼                                                  ▼
┌──────────────────────────────────────────────────────────────┐
│                    Reverse Proxy Layer                       │
│                  (Nginx/Caddy - Optional)                    │
│                                                              │
│  • TLS Termination                                           │
│  • Load Balancing                                            │
│  • Additional Rate Limiting                                  │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTP
                            ▼
┌───────────────────────────────────────────────────────────────┐
│              Rust Verusd RPC Proxy Server                     │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   HTTP Handler                          │ │
│  │  • Request Routing                                       │ │
│  │  • CORS Handling                                        │ │
│  │  • Request ID Generation                                │ │
│  └────────────────────┬────────────────────────────────────┘ │
│                       │                                       │
│  ┌────────────────────▼───────────────────────────────────┐  │
│  │              Security Layer                           │  │
│  │  • IP Filtering (Allowlist/Blocklist)                 │  │
│  │  • API Key Authentication                             │  │
│  │  • Audit Logging                                      │  │
│  └────────────────────┬───────────────────────────────────┘  │
│                       │                                       │
│  ┌────────────────────▼───────────────────────────────────┐  │
│  │            Rate Limiting Layer                        │  │
│  │  • Per-IP Rate Limiting                               │  │
│  │  • Per-Method Rate Limiting                           │  │
│  │  • Token Bucket Algorithm                             │  │
│  └────────────────────┬───────────────────────────────────┘  │
│                       │                                       │
│  ┌────────────────────▼───────────────────────────────────┐  │
│  │           Request Processing Layer                    │  │
│  │  • Method Allowlist Validation                        │  │
│  │  • Parameter Validation                               │  │
│  │  • Response Caching (read-only methods)               │  │
│  └────────────────────┬───────────────────────────────────┘  │
│                       │                                       │
│  ┌────────────────────▼───────────────────────────────────┐  │
│  │        Upstream Communication Layer                   │  │
│  │  • Circuit Breaker                                     │  │
│  │  • Request Timeout                                     │  │
│  │  • Connection Pooling (future)                         │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │            Observability Layer                        │  │
│  │  • Prometheus Metrics                                  │  │
│  │  • Structured Logging (tracing)                        │  │
│  │  • Health/Readiness Endpoints                         │  │
│  └───────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. HTTP Server (`main.rs`)

**Responsibility**: Handle incoming HTTP requests and coordinate the request/response flow.

**Key Features**:
- Built on Hyper 1.x for high performance
- Async/await with Tokio runtime
- Request routing to appropriate handlers
- Graceful shutdown support

**Implementation**:
```rust
async fn handle_req(
    req: Request<hyper::body::Incoming>,
    rpc: Arc<VerusRPC>,
    client_ip: IpAddr,
    server_config: Arc<ServerConfig>,
) -> Result<Response<Full<bytes::Bytes>>>
```

### 2. Authentication & Authorization (`main.rs`)

**Responsibility**: Validate API keys and authorize requests.

**Key Features**:
- Constant-time API key comparison (prevents timing attacks)
- Support for multiple API keys
- Two authentication methods: `X-API-Key` header and `Authorization: Bearer` header
- Audit logging for authentication events

**Security Measures**:
- Constant-time comparison using XOR operation
- No credential logging (only authentication events)
- Rate limiting on failed authentication attempts

### 3. Rate Limiting (`rate_limit.rs`)

**Responsibility**: Prevent abuse through request rate control.

**Architecture**:
- **Global Limiter**: Per-IP rate limit across all methods
- **Method Limiters**: Per-IP, per-method rate limits for expensive operations

**Algorithm**: Token bucket with configurable refill rate and burst capacity

**Implementation**:
```rust
pub struct AdvancedRateLimiter {
    global_limiter: RateLimiter<IpAddr, DashMap<IpAddr, InMemoryState>, DefaultClock>,
    method_limiters: DashMap<String, RateLimiter<...>>,
}
```

**Concurrency**: Lock-free DashMap for thread-safe access

### 4. Method Allowlist (`allowlist.rs`, `allowlist_config.rs`)

**Responsibility**: Control which RPC methods are accessible.

**Presets**:
- **Readonly**: Only safe, read-only methods (e.g., `getinfo`, `getblock`)
- **Standard**: Readonly + some additional safe methods
- **Full**: All methods (use with caution)

**Validation**:
- Method name validation
- Parameter count validation
- Parameter type validation (basic)

### 5. Response Caching (`cache.rs`)

**Responsibility**: Cache responses for frequently requested data.

**Algorithm**: LRU (Least Recently Used) cache with configurable size

**Key Features**:
- Only caches cacheable methods (e.g., `getblock`, `getrawtransaction`)
- Cache key includes method name and parameters
- TTL support for cache invalidation (future enhancement)

**Thread Safety**: Uses `Arc<Mutex<LruCache>>` for concurrent access

### 6. Audit Logging (`audit.rs`)

**Responsibility**: Log security-sensitive events for compliance and forensics.

**Events Logged**:
- Authentication attempts (success and failure)
- Rate limit violations
- IP access denials
- Invalid requests
- RPC errors

**Format**: Structured JSON logs with sanitized input (prevents log injection)

### 7. IP Filtering (`ip_filter.rs`)

**Responsibility**: Allow or block requests based on client IP addresses.

**Modes**:
- **Allowlist**: Only specified IPs/networks are allowed
- **Blocklist**: Specified IPs/networks are blocked
- **Disabled**: No IP filtering

**Features**:
- CIDR notation support (e.g., `10.0.0.0/8`)
- Both IPv4 and IPv6 support

### 8. Circuit Breaker (`circuit_breaker.rs`)

**Responsibility**: Prevent cascading failures when upstream is unavailable.

**States**:
- **Closed**: Normal operation, requests pass through
- **Open**: Too many failures, fast-fail without calling upstream
- **Half-Open**: Testing if service recovered

**Configuration**:
- Failure threshold (number of failures before opening)
- Timeout (duration to wait before testing recovery)
- Success threshold (successes needed to close circuit)

**Note**: Currently implemented but not integrated (future enhancement)

### 9. Metrics (`metrics.rs`)

**Responsibility**: Expose operational metrics for monitoring.

**Metrics Provided**:
- Request counts by method
- Request durations (histogram)
- Error counts by type
- Rate limit hits
- Authentication failures
- Cache hit/miss ratios

**Format**: Prometheus text exposition format

**Endpoint**: `/metrics`

### 10. Configuration (`config.rs`, `config_types.rs`)

**Responsibility**: Load and validate configuration from multiple sources.

**Configuration Sources** (in order of precedence):
1. Environment variables (`VERUS_RPC_*`)
2. Configuration file (`Conf.toml`)
3. Default values

**Validation**:
- Required fields must be present
- Credentials must meet minimum security standards
- Network addresses must be valid
- Rate limits must be positive

## Request Flow

### 1. Incoming Request

```
Client → HTTP Request → Server
```

1. Connection accepted by TCP listener
2. Request parsed by Hyper
3. Request ID (UUID) generated
4. Logging span created with request ID and client IP

### 2. Initial Validation

```
HTTP Handler → CORS Check → Content-Type Check → Size Check
```

1. **CORS**: Validate Origin header, add CORS headers to response
2. **Content-Type**: Ensure `application/json`
3. **Size**: Reject requests larger than 50MB

### 3. Security Checks

```
IP Filter → Authentication → Audit Log
```

1. **IP Filtering**: Check if client IP is allowed
2. **Authentication**: Validate API key if required (except `/health`, `/ready`)
3. **Audit Logging**: Log authentication result

### 4. Rate Limiting

```
Global Rate Limit → Method-Specific Rate Limit
```

1. Check global per-IP rate limit
2. If method-specific limit configured, check it
3. Return 429 if rate limit exceeded

### 5. Request Processing

```
Parse JSON → Validate Method → Check Cache → Forward to RPC
```

1. **Parse**: Deserialize JSON-RPC request
2. **Validate**: Check method against allowlist
3. **Cache Check**: For cacheable methods, check if result is cached
4. **Forward**: Send request to upstream Verus daemon

### 6. Response Handling

```
RPC Response → Update Cache → Add Headers → Send Response
```

1. Receive response from upstream
2. Update cache for cacheable methods
3. Add response headers (CORS, Request-ID, etc.)
4. Send response to client

### 7. Error Handling

```
Error → Log → Audit → Error Response
```

1. Catch and categorize errors
2. Log error with context
3. Audit log if security-relevant
4. Return appropriate error response (JSON-RPC format)

## Security Model

### Defense in Depth

The server implements multiple layers of security:

1. **Network Layer**: IP filtering, reverse proxy with TLS
2. **Application Layer**: API key authentication, rate limiting
3. **Data Layer**: Input validation, output sanitization

### Threat Model

**Threats Addressed**:
- **Unauthorized Access**: API key authentication
- **Brute Force**: Rate limiting
- **DDoS**: Rate limiting, connection limits, circuit breaker
- **Injection Attacks**: Input validation, parameterized queries
- **Information Disclosure**: Audit logging, error message sanitization
- **Timing Attacks**: Constant-time API key comparison

**Threats NOT Addressed** (require external solutions):
- **Network-level DDoS**: Use DDoS protection service (Cloudflare, etc.)
- **TLS Termination**: Use reverse proxy (Nginx, Caddy)
- **Credential Theft**: Use secure key management (secrets manager)

### Authentication Flow

```
1. Client includes API key in request header
   ↓
2. Server extracts key (X-API-Key or Authorization: Bearer)
   ↓
3. Constant-time comparison against configured keys
   ↓
4. If valid: Log success, allow request
   If invalid: Log failure, return 401
   If missing: Log missing, return 401
```

### Audit Trail

All security-sensitive events are logged with:
- Timestamp
- Request ID
- Client IP
- Event type
- Outcome (success/failure)
- Failure reason (if applicable)

Logs are written to stdout in structured format (JSON) for easy parsing and analysis.

## Performance Considerations

### Concurrency Model

**Async/Await**: All I/O operations are async to avoid blocking threads

**Thread Pool**: Tokio manages a work-stealing thread pool

**Lock-Free Data Structures**: DashMap used for concurrent rate limiting

### Memory Management

**Connection Pooling**: HTTP/1.1 keepalive for upstream connections

**Cache Size Limits**: LRU cache prevents unbounded memory growth

**Request Size Limits**: 50MB maximum request size

### Optimization Strategies

1. **Early Validation**: Reject invalid requests before expensive operations
2. **Response Caching**: Avoid redundant upstream calls for immutable data
3. **Zero-Copy**: Minimize data copying where possible
4. **Efficient Serialization**: serde_json with optimized settings

### Scalability

**Horizontal Scaling**: Stateless design allows multiple instances behind load balancer

**Vertical Scaling**: Async model efficiently utilizes multiple CPU cores

**Bottlenecks**:
- Upstream RPC daemon (single point of failure)
- Response cache (memory limited)
- Rate limiting (per-instance, not distributed)

## Design Decisions

### Why Rust?

- **Performance**: Comparable to C/C++ with memory safety
- **Concurrency**: Fearless concurrency with the borrow checker
- **Reliability**: Type system catches bugs at compile time
- **Ecosystem**: Excellent async/await support with Tokio

### Why Hyper 1.x?

- **Performance**: One of the fastest HTTP libraries
- **Flexibility**: Low-level control for custom logic
- **Async**: Native async/await support
- **Stability**: Battle-tested in production

### Why Token Bucket for Rate Limiting?

- **Fairness**: Allows short bursts while limiting sustained rate
- **Simplicity**: Easy to understand and configure
- **Performance**: O(1) check operation

### Why LRU for Caching?

- **Predictable**: Bounded memory usage
- **Effective**: Good hit rate for typical workloads
- **Simple**: Easy to implement and reason about

### Why Not Connection Pooling (Yet)?

- **Complexity**: Adds significant complexity
- **Upstream**: Verus daemon is typically single-instance
- **Future**: Planned for future release with multiple upstreams

### Configuration Philosophy

**Secure by Default**: Restrictive defaults, opt-in for permissive settings

**Environment Variables**: Twelve-factor app pattern for containerization

**Fail Fast**: Invalid configuration causes startup failure

## Future Enhancements

### Planned Features

1. **Connection Pooling**: Multiple upstream connections
2. **Circuit Breaker Integration**: Automatic failover
3. **Distributed Rate Limiting**: Redis-backed rate limits
4. **Advanced Caching**: TTL, invalidation strategies
5. **Request Transformation**: Custom middleware support
6. **mTLS**: Mutual TLS for upstream communication
7. **gRPC Support**: Alternative to JSON-RPC

### Research Areas

1. **Load Balancing**: Intelligent request routing to multiple upstreams
2. **Caching Strategies**: Adaptive caching based on request patterns
3. **Security Hardening**: Additional validation, sandboxing
4. **Performance Tuning**: Profiling and optimization

## Contributing

When making architectural changes, please:

1. Update this document
2. Add tests for new components
3. Update relevant documentation
4. Discuss breaking changes in issues first

## References

- [Hyper Documentation](https://hyper.rs/)
- [Tokio Documentation](https://tokio.rs/)
- [Governor (Rate Limiting)](https://github.com/boinkor-net/governor)
- [Verus RPC Reference](https://verus.io/developers/)
