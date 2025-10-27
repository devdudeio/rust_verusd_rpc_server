//! Rust Verusd RPC Server
//!
//! A high-performance, secure JSON-RPC proxy server for Verus blockchain nodes.
//! This server sits between clients and the Verus daemon, providing enhanced
//! security features including:
//!
//! - **API Key Authentication**: Protect RPC endpoints with configurable API keys
//! - **Per-IP Rate Limiting**: Prevent abuse with token bucket rate limiting
//! - **Method Allowlisting**: Only approved RPC methods are forwarded
//! - **Input Validation**: Strict parameter validation to prevent injection attacks
//! - **CORS Configuration**: Control which origins can access the API
//! - **Request Tracing**: Every request gets a unique ID for correlation
//! - **Health Checks**: `/health` endpoint for monitoring and load balancers
//! - **Graceful Shutdown**: Proper SIGTERM/SIGINT handling with connection draining
//!
//! # Configuration
//!
//! The server can be configured via `Conf.toml` or environment variables with the
//! `VERUS_RPC_` prefix. Environment variables override file-based configuration.
//!
//! # Example
//!
//! ```bash
//! # Start with file configuration
//! cargo run
//!
//! # Start with environment variables
//! VERUS_RPC_RPC_URL=http://localhost:27486 \
//! VERUS_RPC_RPC_USER=user \
//! VERUS_RPC_RPC_PASSWORD=pass \
//! VERUS_RPC_SERVER_PORT=8080 \
//! VERUS_RPC_SERVER_ADDR=0.0.0.0 \
//! cargo run
//! ```

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jsonrpc::simple_http::{self, SimpleHttpTransport};
use jsonrpc::{error::RpcError, Client};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod allowlist;
mod allowlist_config;
mod audit;
mod auth;
mod cache;
mod config;
mod config_types;
mod ip_filter;
mod metrics;
mod rate_limit;

/// Maximum allowed request body size in bytes (50 MiB).
///
/// Requests larger than this will be rejected with a 413 Payload Too Large error.
const MAX_CONTENT_LENGTH: u64 = 1024 * 1024 * 50;

/// Validates security-sensitive configuration values and warns about insecure settings.
///
/// This function performs various security checks on the configuration to help prevent
/// common misconfigurations that could lead to security vulnerabilities.
///
/// # Arguments
///
/// * `rpc_user` - The RPC username
/// * `rpc_password` - The RPC password
/// * `api_keys` - Optional set of API keys
/// * `cors_origins` - List of allowed CORS origins
/// * `server_addr` - The server bind address
///
/// # Security Checks
///
/// * RPC credentials must not be default/common values
/// * RPC password must be at least 12 characters
/// * API keys must be at least 16 characters
/// * Warns if API keys are not enabled in production
/// * Warns if CORS allows all origins (*)
/// * Warns if binding to 0.0.0.0 without API keys
fn validate_security_configuration(
    rpc_user: &str,
    rpc_password: &str,
    api_keys: &Option<HashSet<String>>,
    cors_origins: &[String],
    server_addr: &str,
) {
    // Common default credentials that should never be used
    const COMMON_PASSWORDS: &[&str] = &[
        "password",
        "testpassword",
        "test",
        "admin",
        "root",
        "changeme",
        "123456",
        "password123",
    ];

    const COMMON_USERNAMES: &[&str] = &["testuser", "admin", "root", "test", "user"];

    // Check for common/default RPC credentials
    if COMMON_USERNAMES.contains(&rpc_user) {
        warn!(
            "⚠️  SECURITY WARNING: RPC username '{}' is a common default. Use a unique username for production.",
            rpc_user
        );
    }

    if COMMON_PASSWORDS.contains(&rpc_password) {
        error!(
            "🔴 CRITICAL SECURITY ISSUE: RPC password is a common default value! Change immediately!"
        );
    }

    // Check RPC password strength
    if rpc_password.len() < 12 {
        warn!(
            "⚠️  SECURITY WARNING: RPC password is only {} characters. Recommend at least 12 characters.",
            rpc_password.len()
        );
    }

    // Validate API keys
    match api_keys {
        Some(keys) => {
            for key in keys {
                if key.len() < 16 {
                    warn!(
                        "⚠️  SECURITY WARNING: API key is only {} characters. Recommend at least 16 characters for production.",
                        key.len()
                    );
                }

                // Check for simple/common API keys
                if key == "test"
                    || key == "testkey"
                    || key == "apikey"
                    || key == "key"
                    || key.chars().all(|c| c.is_numeric())
                {
                    error!(
                        "🔴 CRITICAL SECURITY ISSUE: API key '{}' is too simple! Use a strong, random key.",
                        key
                    );
                }
            }
        }
        None => {
            if server_addr == "0.0.0.0" {
                error!(
                    "🔴 CRITICAL SECURITY ISSUE: Server is publicly accessible (0.0.0.0) without API key authentication!"
                );
                warn!("   Set api_keys in configuration to enable authentication.");
            } else {
                warn!("⚠️  SECURITY WARNING: API key authentication is disabled. Not recommended for production.");
            }
        }
    }

    // Validate CORS configuration
    if cors_origins.len() == 1 && cors_origins[0] == "*" {
        warn!(
            "⚠️  SECURITY WARNING: CORS allows all origins (*). Specify exact origins for production."
        );
    }

    // Check for public binding without authentication
    if server_addr == "0.0.0.0" && api_keys.is_none() {
        error!("🔴 CRITICAL: Binding to 0.0.0.0 without API keys exposes your RPC endpoint to the internet!");
        warn!("   Either bind to 127.0.0.1 or enable API key authentication.");
    }
}

/// Server configuration settings.
///
/// Contains all shared systems and configuration for request handlers.
struct ServerConfig {
    /// Optional set of valid API keys for authentication (legacy mode).
    ///
    /// If `None`, API key authentication is disabled (not recommended for production).
    /// If `Some`, requests must include a valid key via the `X-API-Key` header or
    /// `Authorization: Bearer` token.
    api_keys: Option<HashSet<String>>,

    /// List of allowed CORS origins.
    ///
    /// Can contain exact origins like `"https://example.com"` or `"*"` to allow all.
    /// For security, wildcard should only be used in development.
    cors_origins: Vec<String>,

    /// IP access filter for allowlist/blocklist.
    ip_filter: ip_filter::IpFilter,

    /// Audit logger for security events.
    audit_logger: audit::AuditLogger,

    /// Response cache for frequently requested data.
    cache: Option<cache::ResponseCache>,

    /// Advanced rate limiter with per-method limits.
    rate_limiter: rate_limit::AdvancedRateLimiter,
}

/// JSON-RPC client wrapper for communicating with the Verus daemon.
///
/// Handles request forwarding, allowlist validation, and timeout management.
struct VerusRPC {
    /// Underlying JSON-RPC client for HTTP transport.
    client: Client,

    /// Timeout duration for RPC requests.
    timeout: Duration,

    /// Method allowlist for validating RPC requests.
    allowlist: allowlist::Allowlist,
}

impl VerusRPC {
    /// Creates a new RPC client connected to the Verus daemon.
    ///
    /// # Arguments
    ///
    /// * `url` - The RPC endpoint URL (e.g., `http://localhost:27486`)
    /// * `user` - RPC username for authentication
    /// * `pass` - RPC password for authentication
    /// * `timeout` - Request timeout duration
    /// * `allowlist` - Method allowlist for validating RPC requests
    ///
    /// # Returns
    ///
    /// * `Ok(VerusRPC)` - Successfully created RPC client
    /// * `Err` - If the URL is invalid or transport setup fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// # use rust_verusd_rpc_server::VerusRPC;
    ///
    /// let rpc = VerusRPC::new(
    ///     "http://localhost:27486",
    ///     "user",
    ///     "pass",
    ///     Duration::from_secs(30),
    ///     allowlist
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn new(
        url: &str,
        user: &str,
        pass: &str,
        timeout: Duration,
        allowlist: allowlist::Allowlist,
    ) -> Result<VerusRPC, simple_http::Error> {
        let transport = SimpleHttpTransport::builder()
            .url(url)?
            .auth(user, Some(pass))
            .build();
        Ok(VerusRPC {
            client: Client::with_transport(transport),
            timeout,
            allowlist,
        })
    }

    /// Handles a JSON-RPC request with allowlist validation and parameter checking.
    ///
    /// This method performs several security checks:
    /// 1. Validates the method name exists in the request
    /// 2. Parses and validates parameters
    /// 3. Checks method and parameters against the allowlist
    /// 4. Forwards the request to the Verus daemon with timeout
    ///
    /// # Arguments
    ///
    /// * `req_body` - The JSON-RPC request body
    ///
    /// # Returns
    ///
    /// * `Ok(Value)` - The RPC response result
    /// * `Err(RpcError)` - If validation fails or the RPC call errors
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The method parameter is missing or invalid (-32602)
    /// * The params parameter is missing or invalid (-32602)
    /// * The method is not in the allowlist (-32601)
    /// * The RPC request times out (-32603)
    /// * The upstream RPC call fails (varies)
    async fn handle(&self, req_body: Value) -> Result<Value, RpcError> {
        let method = match req_body["method"].as_str() {
            Some(method) => method,
            None => {
                warn!("Missing or invalid method parameter");
                return Err(RpcError {
                    code: -32602,
                    message: "Invalid method parameter".into(),
                    data: None,
                });
            }
        };

        debug!("Processing RPC method: {}", method);

        let params: Result<Vec<Box<RawValue>>, RpcError> = match req_body["params"].as_array() {
            Some(params) => {
                params
                    .iter()
                    .enumerate()
                    .map(|(i, v)| {
                        if method == "getblock" && i == 0 {
                            if let Ok(num) = v.to_string().parse::<i64>() {
                                // Legacy hack because getblock in JS used to allow
                                // strings to be passed in clientside and the former JS rpc server
                                // wouldn't care. This will be deprecated in the future and shouldn't
                                // be relied upon.
                                RawValue::from_string(format!("\"{}\"", num)).map_err(|e| {
                                    error!(
                                        "Failed to create RawValue for getblock parameter: {}",
                                        e
                                    );
                                    RpcError {
                                        code: -32602,
                                        message: "Invalid parameter format".into(),
                                        data: None,
                                    }
                                })
                            } else {
                                RawValue::from_string(v.to_string()).map_err(|e| {
                                    error!("Failed to create RawValue: {}", e);
                                    RpcError {
                                        code: -32602,
                                        message: "Invalid parameter format".into(),
                                        data: None,
                                    }
                                })
                            }
                        } else {
                            RawValue::from_string(v.to_string()).map_err(|e| {
                                error!("Failed to create RawValue: {}", e);
                                RpcError {
                                    code: -32602,
                                    message: "Invalid parameter format".into(),
                                    data: None,
                                }
                            })
                        }
                    })
                    .collect()
            }
            None => {
                warn!("Missing or invalid params parameter");
                Err(RpcError {
                    code: -32602,
                    message: "Invalid params parameter".into(),
                    data: None,
                })
            }
        };

        let params = params?;

        if !self.allowlist.is_method_allowed(method, &params) {
            warn!("Method not allowed or invalid parameters: {}", method);
            return Err(RpcError {
                code: -32601,
                message: "Method not found".into(),
                data: None,
            });
        }

        // Convert Vec<Box<RawValue>> into a single RawValue containing the params array
        let params_array_str = format!(
            "[{}]",
            params.iter().map(|p| p.get()).collect::<Vec<_>>().join(",")
        );
        let params_raw = RawValue::from_string(params_array_str).map_err(|e| {
            error!("Failed to serialize params: {}", e);
            RpcError {
                code: -32603,
                message: "Internal error".into(),
                data: None,
            }
        })?;

        let request = self.client.build_request(method, Some(&params_raw));

        // Wrap RPC call with timeout
        let response =
            tokio::time::timeout(self.timeout, async { self.client.send_request(request) })
                .await
                .map_err(|_| {
                    error!("RPC request timed out after {:?}", self.timeout);
                    RpcError {
                        code: -32603,
                        message: format!("Request timed out after {:?}", self.timeout),
                        data: None,
                    }
                })?
                .map_err(|e| {
                    error!("RPC request failed: {:?}", e);
                    match e {
                        jsonrpc::Error::Rpc(rpc_error) => rpc_error,
                        _ => RpcError {
                            code: -32603,
                            message: "Internal error".into(),
                            data: None,
                        },
                    }
                })?;

        let result: Value = response.result().map_err(|e| {
            error!("RPC response parsing failed: {:?}", e);
            match e {
                jsonrpc::Error::Rpc(rpc_error) => rpc_error,
                _ => RpcError {
                    code: -32603,
                    message: "Internal error".into(),
                    data: None,
                },
            }
        })?;

        debug!("RPC request successful");
        Ok(result)
    }

    /// Performs a health check by calling the `getinfo` RPC method.
    ///
    /// This is used by the `/health` endpoint to verify the upstream RPC
    /// connection is working correctly.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - RPC is healthy and responding
    /// * `Err(String)` - RPC is unhealthy with error description
    async fn health_check(&self) -> Result<(), String> {
        let check_request = json!({
            "method": "getinfo",
            "params": []
        });

        match tokio::time::timeout(self.timeout, async { self.handle(check_request).await }).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("RPC error: {}", e.message)),
            Err(_) => Err("RPC timeout".to_string()),
        }
    }
}

/// Validates an API key using constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `provided_key` - The API key provided by the client
/// * `valid_keys` - Set of valid API keys
///
/// # Returns
///
/// * `true` if the provided key matches any valid key
/// * `false` otherwise
///
/// # Security
///
/// This function uses constant-time comparison to prevent timing attacks that
/// could leak information about valid API keys. For each byte position, the
/// function compares all keys at that position before moving to the next byte,
/// ensuring the execution time depends only on key length, not key content.
fn validate_api_key(provided_key: &str, valid_keys: &HashSet<String>) -> bool {
    // Use constant-time comparison for each valid key
    valid_keys.iter().any(|valid_key| {
        // First check lengths match (this is safe to short-circuit)
        if provided_key.len() != valid_key.len() {
            return false;
        }

        // Constant-time comparison of bytes
        let provided_bytes = provided_key.as_bytes();
        let valid_bytes = valid_key.as_bytes();

        let mut result = 0u8;
        for i in 0..provided_bytes.len() {
            result |= provided_bytes[i] ^ valid_bytes[i];
        }

        result == 0
    })
}

/// Checks API key authentication for a request.
///
/// # Arguments
///
/// * `req` - The HTTP request
/// * `server_config` - Server configuration containing API keys
/// * `request_id` - Unique request ID for tracing
/// * `request_origin` - Origin header from the request
///
/// # Returns
///
/// * `Ok(())` - Authentication successful or not required
/// * `Err(Response)` - Authentication failed, returns error response
fn check_authentication(
    req: &Request<hyper::body::Incoming>,
    server_config: &ServerConfig,
    request_id: &str,
    request_origin: Option<&String>,
) -> Result<(), Box<Response<Full<bytes::Bytes>>>> {
    // Skip authentication for health and readiness checks
    if req.uri().path() == "/health" || req.uri().path() == "/ready" {
        return Ok(());
    }

    if let Some(ref api_keys) = server_config.api_keys {
        // Extract API key from headers (X-API-Key or Authorization: Bearer)
        let provided_key = req
            .headers()
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
            .or_else(|| {
                req.headers()
                    .get(hyper::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|auth| auth.strip_prefix("Bearer "))
            });

        match provided_key {
            Some(key) if validate_api_key(key, api_keys) => {
                debug!("API key authentication successful");
                Ok(())
            }
            Some(_) => {
                warn!("Invalid API key provided");
                let mut response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Full::new(bytes::Bytes::from(
                        json!({
                            "error": {
                                "code": -32001,
                                "message": "Invalid API key",
                                "request_id": request_id
                            }
                        })
                        .to_string(),
                    )))
                    .expect("Failed to build authentication error response");
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                add_cors_and_security_headers(
                    &mut response,
                    &server_config.cors_origins,
                    request_origin,
                );
                Err(Box::new(response))
            }
            None => {
                warn!("Missing API key");
                let mut response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Full::new(bytes::Bytes::from(
                        json!({
                            "error": {
                                "code": -32001,
                                "message": "API key required. Provide via X-API-Key header or Authorization: Bearer token",
                                "request_id": request_id
                            }
                        })
                        .to_string(),
                    )))
                    .expect("Failed to build authentication error response");
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                add_cors_and_security_headers(
                    &mut response,
                    &server_config.cors_origins,
                    request_origin,
                );
                Err(Box::new(response))
            }
        }
    } else {
        Ok(())
    }
}

/// Checks rate limiting for a client IP address with optional per-method limits.
///
/// # Arguments
///
/// * `req` - The HTTP request
/// * `client_ip` - Client's IP address
/// * `method` - Optional RPC method name for per-method rate limiting
/// * `request_id` - Unique request ID for tracing
/// * `server_config` - Server configuration
/// * `request_origin` - Origin header from the request
///
/// # Returns
///
/// * `Ok(())` - Rate limit check passed
/// * `Err(Response)` - Rate limit exceeded, returns error response
fn check_rate_limit(
    req: &Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    method: Option<&str>,
    request_id: &str,
    server_config: &ServerConfig,
    request_origin: Option<&String>,
) -> Result<(), Box<Response<Full<bytes::Bytes>>>> {
    // Skip rate limiting for health, readiness, and metrics checks
    let path = req.uri().path();
    if path == "/health" || path == "/ready" || path == "/metrics" {
        return Ok(());
    }

    match server_config.rate_limiter.check(client_ip, method) {
        Ok(_) => {
            debug!(
                "Rate limit check passed for IP {} method {:?}",
                client_ip, method
            );
            Ok(())
        }
        Err(limit_type) => {
            warn!(
                "Rate limit exceeded for IP {} (limit: {})",
                client_ip, limit_type
            );

            // Log rate limit event
            server_config
                .audit_logger
                .log_rate_limit(&audit::RateLimitEvent {
                    request_id: request_id.to_string(),
                    client_ip,
                    limit_type,
                });

            let mut response = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(Full::new(bytes::Bytes::from(
                    json!({
                        "error": {
                            "code": -32005,
                            "message": "Rate limit exceeded. Please try again later.",
                            "request_id": request_id
                        }
                    })
                    .to_string(),
                )))
                .expect("Failed to build rate limit response");
            response.headers_mut().insert(
                "X-Request-ID",
                request_id
                    .parse()
                    .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
            );
            response
                .headers_mut()
                .insert("Retry-After", hyper::header::HeaderValue::from_static("60"));
            add_cors_and_security_headers(
                &mut response,
                &server_config.cors_origins,
                request_origin,
            );

            // Update metrics
            metrics::RATE_LIMIT_HITS_TOTAL
                .with_label_values(&[&client_ip.to_string(), method.unwrap_or("unknown")])
                .inc();

            Err(Box::new(response))
        }
    }
}

/// Adds CORS and security headers to an HTTP response.
///
/// This function adds appropriate CORS headers based on the configured allowed origins
/// and the request's Origin header. It also adds security headers to protect against
/// common web vulnerabilities.
///
/// # Security Headers Added
///
/// * `Access-Control-Allow-Origin` - CORS origin (if allowed)
/// * `Access-Control-Allow-Methods` - Allowed HTTP methods
/// * `Access-Control-Allow-Headers` - Allowed request headers
/// * `Access-Control-Max-Age` - Preflight cache duration (3600s)
/// * `Access-Control-Expose-Headers` - Headers exposed to client
/// * `Referrer-Policy` - Controls referrer information
/// * `X-Content-Type-Options` - Prevents MIME sniffing
/// * `X-Frame-Options` - Prevents clickjacking
/// * `X-XSS-Protection` - Legacy XSS protection
/// * `Content-Type` - application/json
///
/// # Arguments
///
/// * `response` - The HTTP response to modify
/// * `cors_origins` - List of allowed CORS origins
/// * `request_origin` - The Origin header from the request, if present
///
/// # Behavior
///
/// * If `cors_origins` contains `"*"`, all origins are allowed
/// * If `request_origin` matches an entry in `cors_origins`, that origin is allowed
/// * If no match, CORS headers are not set (request will fail in browser)
fn add_cors_and_security_headers(
    response: &mut Response<Full<bytes::Bytes>>,
    cors_origins: &[String],
    request_origin: Option<&String>,
) {
    use hyper::header::HeaderValue;
    let headers = response.headers_mut();

    // CORS headers - set origin based on configuration
    let allowed_origin = if cors_origins.len() == 1 && cors_origins[0] == "*" {
        // Allow all origins
        HeaderValue::from_static("*")
    } else if let Some(origin) = request_origin {
        // Check if request origin is in allowed list
        if cors_origins.iter().any(|allowed| allowed == origin) {
            HeaderValue::from_str(origin).unwrap_or_else(|_| HeaderValue::from_static("*"))
        } else {
            // Origin not allowed, don't set CORS headers
            HeaderValue::from_static("")
        }
    } else {
        // No origin in request, use first allowed or deny
        if !cors_origins.is_empty() {
            HeaderValue::from_str(&cors_origins[0])
                .unwrap_or_else(|_| HeaderValue::from_static("*"))
        } else {
            HeaderValue::from_static("*")
        }
    };

    if !allowed_origin.is_empty() {
        headers.insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origin);
        headers.insert(
            hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, HEAD, PUT, OPTIONS, POST"),
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(
                "Content-Type, Authorization, Accept, X-Request-ID, X-API-Key",
            ),
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("3600"),
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("X-Request-ID"),
        );
    }

    // Security headers
    headers.insert(
        hyper::header::REFERRER_POLICY,
        HeaderValue::from_static("origin-when-cross-origin"),
    );
    headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        hyper::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
}

/// Handles an incoming HTTP request with full security and validation pipeline.
///
/// This is the main request handler that processes all incoming requests. It performs:
/// 1. Request ID generation for tracing
/// 2. API key authentication (if enabled)
/// 3. Per-IP rate limiting (if not a health check)
/// 4. Special handling for health checks and CORS preflight
/// 5. Content-Type validation for POST requests
/// 6. Payload size validation
/// 7. JSON-RPC request proxying with allowlist enforcement
///
/// # Arguments
///
/// * `req` - The incoming HTTP request
/// * `rpc` - Shared RPC client for forwarding requests
/// * `rate_limiter` - Shared rate limiter for IP-based throttling
/// * `client_ip` - The client's IP address
/// * `server_config` - Shared server configuration (API keys, CORS)
///
/// # Returns
///
/// * `Ok(Response)` - HTTP response (may contain success or error)
/// * `Err` - Only for catastrophic failures (connection errors, etc.)
///
/// # Special Endpoints
///
/// * `GET /health` - Returns server health status (bypasses auth and rate limiting)
/// * `OPTIONS *` - CORS preflight response (bypasses auth and rate limiting)
///
/// # Error Responses
///
/// The function returns HTTP error responses for:
/// * 401 Unauthorized - Missing or invalid API key
/// * 413 Payload Too Large - Request body exceeds [`MAX_CONTENT_LENGTH`]
/// * 415 Unsupported Media Type - Invalid or missing Content-Type
/// * 429 Too Many Requests - Rate limit exceeded
async fn handle_req(
    req: Request<hyper::body::Incoming>,
    rpc: Arc<VerusRPC>,
    client_ip: IpAddr,
    server_config: Arc<ServerConfig>,
) -> Result<Response<Full<bytes::Bytes>>> {
    // Generate request ID for correlation
    let request_id = Uuid::new_v4().to_string();
    let span = tracing::info_span!("request", request_id = %request_id, client_ip = %client_ip);
    let _enter = span.enter();

    let path = req.uri().path();
    info!("Incoming {} request to {}", req.method(), path);

    // Extract Origin header for CORS (convert to String to avoid borrow issues)
    let request_origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Check IP filter (except for health/metrics endpoints)
    if path != "/health" && path != "/ready" && path != "/metrics" {
        if !server_config.ip_filter.is_allowed(client_ip) {
            let denial_reason = server_config
                .ip_filter
                .denial_reason(client_ip)
                .unwrap_or_else(|| "IP not allowed".to_string());
            warn!("IP {} denied: {}", client_ip, denial_reason);

            // Log IP denial
            server_config.audit_logger.log_auth(&audit::AuthEvent {
                request_id: request_id.clone(),
                client_ip,
                success: false,
                key_name: None,
                failure_reason: Some(denial_reason.clone()),
            });

            let mut response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(bytes::Bytes::from(
                    json!({
                        "error": {
                            "code": -32002,
                            "message": format!("Access denied: {}", denial_reason),
                            "request_id": request_id
                        }
                    })
                    .to_string(),
                )))
                .context("Failed to build IP denial response")?;
            response.headers_mut().insert(
                "X-Request-ID",
                request_id
                    .parse()
                    .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
            );
            add_cors_and_security_headers(
                &mut response,
                &server_config.cors_origins,
                request_origin.as_ref(),
            );
            return Ok(response);
        }
    }

    // Check API key authentication
    if let Err(response) =
        check_authentication(&req, &server_config, &request_id, request_origin.as_ref())
    {
        return Ok(*response);
    }

    // Check rate limiting (will be called again with method name after parsing request)
    if let Err(response) = check_rate_limit(
        &req,
        client_ip,
        None, // No method known yet
        &request_id,
        &server_config,
        request_origin.as_ref(),
    ) {
        return Ok(*response);
    }

    // Health check endpoint - checks if the application is alive
    if req.uri().path() == "/health" {
        debug!("Health check request");

        let health_status = match rpc.health_check().await {
            Ok(()) => json!({
                "status": "healthy",
                "rpc": "connected"
            }),
            Err(e) => json!({
                "status": "unhealthy",
                "rpc": "disconnected",
                "error": e
            }),
        };

        let mut response = Response::new(Full::new(bytes::Bytes::from(health_status.to_string())));
        response.headers_mut().insert(
            "X-Request-ID",
            request_id
                .parse()
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
        );
        add_cors_and_security_headers(
            &mut response,
            &server_config.cors_origins,
            request_origin.as_ref(),
        );
        return Ok(response);
    }

    // Readiness check endpoint - checks if the application is ready to accept traffic
    if req.uri().path() == "/ready" {
        debug!("Readiness check request");

        // Check if RPC connection is working and responsive
        let ready_status = match rpc.health_check().await {
            Ok(()) => json!({
                "status": "ready",
                "rpc": "ready"
            }),
            Err(e) => {
                // Return 503 Service Unavailable if not ready
                let mut response = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(Full::new(bytes::Bytes::from(
                        json!({
                            "status": "not_ready",
                            "rpc": "not_ready",
                            "error": e
                        })
                        .to_string(),
                    )))
                    .context("Failed to build readiness response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                add_cors_and_security_headers(
                    &mut response,
                    &server_config.cors_origins,
                    request_origin.as_ref(),
                );
                return Ok(response);
            }
        };

        let mut response = Response::new(Full::new(bytes::Bytes::from(ready_status.to_string())));
        response.headers_mut().insert(
            "X-Request-ID",
            request_id
                .parse()
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
        );
        add_cors_and_security_headers(
            &mut response,
            &server_config.cors_origins,
            request_origin.as_ref(),
        );
        return Ok(response);
    }

    // Metrics endpoint - Prometheus-compatible metrics
    if req.uri().path() == "/metrics" {
        debug!("Metrics request");

        match metrics::gather() {
            Ok(metrics_text) => {
                let mut response = Response::new(Full::new(bytes::Bytes::from(metrics_text)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static(
                        "text/plain; version=0.0.4; charset=utf-8",
                    ),
                );
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                return Ok(response);
            }
            Err(e) => {
                error!("Failed to gather metrics: {}", e);
                let mut response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(bytes::Bytes::from("Failed to gather metrics")))
                    .context("Failed to build metrics error response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                return Ok(response);
            }
        }
    }

    // Handle CORS preflight (OPTIONS) request
    if req.method() == hyper::Method::OPTIONS {
        debug!("CORS preflight request");
        let mut response = Response::new(Full::new(bytes::Bytes::new()));
        response.headers_mut().insert(
            "X-Request-ID",
            request_id
                .parse()
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
        );
        add_cors_and_security_headers(
            &mut response,
            &server_config.cors_origins,
            request_origin.as_ref(),
        );
        return Ok(response);
    }

    // Validate Content-Type header for POST requests
    if req.method() == hyper::Method::POST {
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        match content_type {
            Some(ct) if ct.starts_with("application/json") => {
                debug!("Valid Content-Type: {}", ct);
            }
            Some(ct) => {
                warn!("Invalid Content-Type: {}, expected application/json", ct);
                let mut response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(Full::new(bytes::Bytes::from(
                        "Content-Type must be application/json",
                    )))
                    .context("Failed to build response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                add_cors_and_security_headers(
                    &mut response,
                    &server_config.cors_origins,
                    request_origin.as_ref(),
                );
                return Ok(response);
            }
            None => {
                warn!("Missing Content-Type header");
                let mut response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(Full::new(bytes::Bytes::from(
                        "Content-Type header required",
                    )))
                    .context("Failed to build response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id
                        .parse()
                        .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                );
                add_cors_and_security_headers(
                    &mut response,
                    &server_config.cors_origins,
                    request_origin.as_ref(),
                );
                return Ok(response);
            }
        }
    }

    // Check content length
    if let Some(content_length) = req.headers().get(hyper::header::CONTENT_LENGTH) {
        if let Ok(content_length_str) = content_length.to_str() {
            if let Ok(content_length) = content_length_str.parse::<u64>() {
                if content_length > MAX_CONTENT_LENGTH {
                    warn!("Payload too large: {} bytes", content_length);
                    let mut response = Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Full::new(bytes::Bytes::from("Payload too large")))
                        .context("Failed to build response")?;
                    response.headers_mut().insert(
                        "X-Request-ID",
                        request_id
                            .parse()
                            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
                    );
                    add_cors_and_security_headers(
                        &mut response,
                        &server_config.cors_origins,
                        request_origin.as_ref(),
                    );
                    return Ok(response);
                }
            }
        }
    }

    // Read request body
    let whole_body = req
        .collect()
        .await
        .context("Failed to read request body")?
        .to_bytes();

    let str_body =
        String::from_utf8(whole_body.to_vec()).context("Request body is not valid UTF-8")?;

    debug!("Received request body ({} bytes)", str_body.len());

    // Parse JSON and handle RPC request
    let json_body: Result<Value, _> = serde_json::from_str(&str_body);
    let result = match json_body {
        Ok(req_body) => rpc.handle(req_body).await,
        Err(e) => {
            warn!("JSON parse error: {}", e);
            Err(RpcError {
                code: -32700,
                message: "Parse error".into(),
                data: None,
            })
        }
    };

    // Build response
    let body_bytes = match result {
        Ok(res) => {
            info!("Request completed successfully");
            bytes::Bytes::from(json!({"result": res}).to_string())
        }
        Err(err) => {
            warn!("Request failed with error code: {}", err.code);
            bytes::Bytes::from(
                json!({
                    "error": {
                        "code": err.code,
                        "message": err.message,
                        "request_id": &request_id
                    }
                })
                .to_string(),
            )
        }
    };

    let mut response = Response::new(Full::new(body_bytes));
    response.headers_mut().insert(
        "X-Request-ID",
        request_id
            .parse()
            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
    );
    add_cors_and_security_headers(
        &mut response,
        &server_config.cors_origins,
        request_origin.as_ref(),
    );
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Rust Verusd RPC Server");

    // Load configuration from file and environment variables
    let cfg = config::ServerConfiguration::load().context("Failed to load configuration")?;

    info!("Method allowlist preset: {:?}", cfg.methods.preset);

    // Validate security configuration
    info!("Validating security configuration...");
    validate_security_configuration(
        &cfg.rpc_user,
        &cfg.rpc_password,
        &cfg.api_keys,
        &cfg.cors_origins,
        &cfg.server_addr,
    );

    // Initialize metrics system
    if cfg.metrics.enabled {
        info!("Metrics collection: ENABLED at {}", cfg.metrics.endpoint);
        metrics::init();
    } else {
        info!("Metrics collection: DISABLED");
    }

    // Create IP filter
    let ip_filter =
        ip_filter::IpFilter::new(&cfg.ip_access).context("Failed to create IP filter")?;
    info!("IP access control initialized");

    // Create audit logger
    let audit_logger = audit::AuditLogger::new(cfg.audit.clone());
    if cfg.audit.enabled {
        info!("Audit logging: ENABLED");
    } else {
        info!("Audit logging: DISABLED");
    }

    // Create response cache
    let cache = if cfg.cache.enabled {
        info!(
            "Response caching: ENABLED ({} methods, max {} entries)",
            cfg.cache.methods.len(),
            cfg.cache.max_entries
        );
        Some(cache::ResponseCache::new(&cfg.cache))
    } else {
        info!("Response caching: DISABLED");
        None
    };

    // Create advanced rate limiter with per-method limits
    let rate_limiter = rate_limit::AdvancedRateLimiter::new(
        cfg.rate_limit_per_minute,
        cfg.rate_limit_burst,
        cfg.method_rate_limits.clone(),
    )
    .context("Failed to create rate limiter")?;
    info!(
        "Rate limiting: {} requests/minute with burst of {}",
        cfg.rate_limit_per_minute, cfg.rate_limit_burst
    );

    let addr = SocketAddr::from((
        cfg.server_addr
            .parse::<IpAddr>()
            .context("Invalid server address")?,
        cfg.server_port,
    ));

    info!("Connecting to RPC server at {}", cfg.rpc_url);
    info!("Request timeout set to {:?}", cfg.request_timeout);

    // Create method allowlist from configuration
    let allowlist = allowlist::Allowlist::from_config(&cfg.methods);
    info!(
        "Method allowlist initialized with {} allowed methods",
        allowlist.len()
    );

    // Create and validate RPC client
    let rpc = Arc::new(
        VerusRPC::new(
            &cfg.rpc_url,
            &cfg.rpc_user,
            &cfg.rpc_password,
            cfg.request_timeout,
            allowlist,
        )
        .context("Failed to create RPC client")?,
    );

    let server_config = Arc::new(ServerConfig {
        api_keys: cfg.api_keys.clone(),
        cors_origins: cfg.cors_origins.clone(),
        ip_filter,
        audit_logger,
        cache,
        rate_limiter,
    });

    info!("Server listening on {}", addr);
    info!(
        "Health check (liveness) available at http://{}/health",
        addr
    );
    info!("Readiness check available at http://{}/ready", addr);
    if cfg.metrics.enabled {
        info!(
            "Metrics available at http://{}{}",
            addr, cfg.metrics.endpoint
        );
    }
    info!("TLS termination: Use Caddy or nginx as reverse proxy for HTTPS");

    if cfg.api_keys.is_some() {
        info!("API key authentication: ENABLED");
    } else {
        warn!("API key authentication: DISABLED (not recommended for production)");
    }

    if cfg.cors_origins.len() == 1 && cfg.cors_origins[0] == "*" {
        warn!("CORS: Allowing all origins (not recommended for production)");
    } else {
        info!("CORS: Allowing origins: {:?}", cfg.cors_origins);
    }

    // Create TCP listener
    let listener = TcpListener::bind(addr)
        .await
        .context("Failed to bind to address")?;

    // Setup graceful shutdown signal handler
    let shutdown_signal = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C signal");
            },
            _ = terminate => {
                info!("Received SIGTERM signal");
            },
        }
    };

    // Accept connections with graceful shutdown
    let server = async {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            };

            debug!("New connection from {}", remote_addr);

            let rpc_clone = Arc::clone(&rpc);
            let server_config_clone = Arc::clone(&server_config);
            let client_ip = remote_addr.ip();

            // Handle HTTP connection
            tokio::task::spawn(async move {
                let io = TokioIo::new(stream);
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let rpc = Arc::clone(&rpc_clone);
                            let server_config = Arc::clone(&server_config_clone);
                            async move { handle_req(req, rpc, client_ip, server_config).await }
                        }),
                    )
                    .await
                {
                    error!(
                        "Error serving HTTP connection from {}: {:?}",
                        remote_addr, err
                    );
                }
            });
        }
    };

    // Run server until shutdown signal
    tokio::select! {
        _ = server => {
            info!("Server stopped");
        }
        _ = shutdown_signal => {
            info!("Shutting down gracefully...");
        }
    }

    info!("Server shutdown complete");
    Ok(())
}
