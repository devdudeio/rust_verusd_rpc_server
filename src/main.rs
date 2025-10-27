use hyper::{Request, Response, body::Body, StatusCode};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use serde_json::{Value, json};
use jsonrpc::{Client, error::RpcError};
use jsonrpc::simple_http::{self, SimpleHttpTransport};
use serde_json::value::RawValue;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr};
use std::time::Duration;
use std::num::NonZeroU32;
use std::collections::HashSet;
use std::path::Path;
use std::fs::File;
use std::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, pkcs8_private_keys};
use tracing::{info, warn, error, debug, Span};
use anyhow::{Result, Context, anyhow};
use uuid::Uuid;
use governor::{Quota, RateLimiter, Jitter};
use governor::state::{InMemoryState, NotKeyed};
use governor::clock::DefaultClock;
use dashmap::DashMap;

mod allowlist;

// Configuration constants
const MAX_CONTENT_LENGTH: u64 = 1024 * 1024 * 50; // 50 MiB
const DEFAULT_REQUEST_TIMEOUT: u64 = 30; // seconds
const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 60;
const DEFAULT_RATE_LIMIT_BURST: u32 = 10;

// Per-IP rate limiter
type IpRateLimiter = RateLimiter<IpAddr, DashMap<IpAddr, InMemoryState>, DefaultClock>;

struct ServerConfig {
    api_keys: Option<HashSet<String>>,
    cors_origins: Vec<String>,
}

struct VerusRPC {
    client: Client,
    timeout: Duration,
}

impl VerusRPC {
    fn new(url: &str, user: &str, pass: &str, timeout: Duration) -> Result<VerusRPC, simple_http::Error> {
        let transport = SimpleHttpTransport::builder()
            .url(url)?
            .auth(user, Some(pass))
            .build();
        Ok(VerusRPC {
            client: Client::with_transport(transport),
            timeout,
        })
    }

    async fn handle(&self, req_body: Value) -> Result<Value, RpcError> {
        let method = match req_body["method"].as_str() {
            Some(method) => method,
            None => {
                warn!("Missing or invalid method parameter");
                return Err(RpcError {
                    code: -32602,
                    message: "Invalid method parameter".into(),
                    data: None
                });
            }
        };

        debug!("Processing RPC method: {}", method);

        let params: Result<Vec<Box<RawValue>>, RpcError> = match req_body["params"].as_array() {
            Some(params) => {
                params.iter().enumerate().map(|(i, v)| {
                    if method == "getblock" && i == 0 {
                        if let Ok(num) = v.to_string().parse::<i64>() {
                            // Legacy hack because getblock in JS used to allow
                            // strings to be passed in clientside and the former JS rpc server
                            // wouldn't care. This will be deprecated in the future and shouldn't
                            // be relied upon.
                            RawValue::from_string(format!("\"{}\"", num)).map_err(|e| {
                                error!("Failed to create RawValue for getblock parameter: {}", e);
                                RpcError {
                                    code: -32602,
                                    message: "Invalid parameter format".into(),
                                    data: None
                                }
                            })
                        } else {
                            RawValue::from_string(v.to_string()).map_err(|e| {
                                error!("Failed to create RawValue: {}", e);
                                RpcError {
                                    code: -32602,
                                    message: "Invalid parameter format".into(),
                                    data: None
                                }
                            })
                        }
                    } else {
                        RawValue::from_string(v.to_string()).map_err(|e| {
                            error!("Failed to create RawValue: {}", e);
                            RpcError {
                                code: -32602,
                                message: "Invalid parameter format".into(),
                                data: None
                            }
                        })
                    }
                }).collect()
            },
            None => {
                warn!("Missing or invalid params parameter");
                Err(RpcError {
                    code: -32602,
                    message: "Invalid params parameter".into(),
                    data: None
                })
            }
        };

        let params = params?;

        if !allowlist::is_method_allowed(method, &params) {
            warn!("Method not allowed or invalid parameters: {}", method);
            return Err(RpcError {
                code: -32601,
                message: "Method not found".into(),
                data: None
            });
        }

        let request = self.client.build_request(method, &params);

        // Wrap RPC call with timeout
        let response = tokio::time::timeout(self.timeout, async {
            self.client.send_request(request)
        }).await.map_err(|_| {
            error!("RPC request timed out after {:?}", self.timeout);
            RpcError {
                code: -32603,
                message: format!("Request timed out after {:?}", self.timeout),
                data: None
            }
        })?.map_err(|e| {
            error!("RPC request failed: {:?}", e);
            match e {
                jsonrpc::Error::Rpc(rpc_error) => rpc_error,
                _ => RpcError {
                    code: -32603,
                    message: "Internal error".into(),
                    data: None
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
                    data: None
                },
            }
        })?;

        debug!("RPC request successful");
        Ok(result)
    }

    /// Health check that verifies RPC connectivity
    async fn health_check(&self) -> Result<(), String> {
        let check_request = json!({
            "method": "getinfo",
            "params": []
        });

        match tokio::time::timeout(self.timeout, async {
            self.handle(check_request).await
        }).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(format!("RPC error: {}", e.message)),
            Err(_) => Err("RPC timeout".to_string()),
        }
    }
}

/// Load TLS configuration from certificate and key files
fn load_tls_config(cert_path: &str, key_path: &str) -> Result<tokio_rustls::rustls::ServerConfig> {
    // Load certificate chain
    let cert_file = File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<tokio_rustls::rustls::pki_types::CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate file")?;

    if cert_chain.is_empty() {
        return Err(anyhow!("No certificates found in {}", cert_path));
    }

    // Load private key
    let key_file = File::open(key_path)
        .context(format!("Failed to open private key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = pkcs8_private_keys(&mut key_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse private key file")?;

    if keys.is_empty() {
        return Err(anyhow!("No private keys found in {}", key_path));
    }

    let private_key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0));

    // Create TLS config
    let mut config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("Failed to create TLS configuration")?;

    // Configure ALPN for HTTP/1.1
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}

fn add_cors_and_security_headers(
    response: &mut Response<Full<bytes::Bytes>>,
    cors_origins: &[String],
    request_origin: Option<&str>
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
            HeaderValue::from_str(&cors_origins[0]).unwrap_or_else(|_| HeaderValue::from_static("*"))
        } else {
            HeaderValue::from_static("*")
        }
    };

    if !allowed_origin.is_empty() {
        headers.insert(
            hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            allowed_origin
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, HEAD, PUT, OPTIONS, POST")
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization, Accept, X-Request-ID, X-API-Key")
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("3600")
        );
        headers.insert(
            hyper::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("X-Request-ID")
        );
    }

    // Security headers
    headers.insert(
        hyper::header::REFERRER_POLICY,
        HeaderValue::from_static("origin-when-cross-origin")
    );
    headers.insert(
        hyper::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff")
    );
    headers.insert(
        hyper::header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY")
    );
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block")
    );
    headers.insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json")
    );
}

async fn handle_req(
    req: Request<hyper::body::Incoming>,
    rpc: Arc<VerusRPC>,
    rate_limiter: Arc<IpRateLimiter>,
    client_ip: IpAddr,
    server_config: Arc<ServerConfig>
) -> Result<Response<Full<bytes::Bytes>>> {
    // Generate request ID for correlation
    let request_id = Uuid::new_v4().to_string();
    let span = tracing::info_span!("request", request_id = %request_id, client_ip = %client_ip);
    let _enter = span.enter();

    info!("Incoming {} request to {}", req.method(), req.uri().path());

    // Extract Origin header for CORS
    let request_origin = req.headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok());

    // Check API key authentication (skip health checks)
    if req.uri().path() != "/health" {
        if let Some(ref api_keys) = server_config.api_keys {
            // Extract API key from headers (X-API-Key or Authorization: Bearer)
            let provided_key = req.headers()
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                .or_else(|| {
                    req.headers()
                        .get(hyper::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|auth| {
                            if auth.starts_with("Bearer ") {
                                Some(&auth[7..])
                            } else {
                                None
                            }
                        })
                });

            match provided_key {
                Some(key) if api_keys.contains(key) => {
                    debug!("API key authentication successful");
                }
                Some(_) => {
                    warn!("Invalid API key provided");
                    let mut response = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Full::new(bytes::Bytes::from(json!({
                            "error": {
                                "code": -32001,
                                "message": "Invalid API key",
                                "request_id": &request_id
                            }
                        }).to_string())))
                        .context("Failed to build authentication error response")?;
                    response.headers_mut().insert(
                        "X-Request-ID",
                        request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
                    );
                    add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
                    return Ok(response);
                }
                None => {
                    warn!("Missing API key");
                    let mut response = Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Full::new(bytes::Bytes::from(json!({
                            "error": {
                                "code": -32001,
                                "message": "API key required. Provide via X-API-Key header or Authorization: Bearer token",
                                "request_id": &request_id
                            }
                        }).to_string())))
                        .context("Failed to build authentication error response")?;
                    response.headers_mut().insert(
                        "X-Request-ID",
                        request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
                    );
                    add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
                    return Ok(response);
                }
            }
        }
    }

    // Check rate limit for this IP (skip health checks)
    if req.uri().path() != "/health" {
        match rate_limiter.check_key(&client_ip) {
            Ok(_) => {
                debug!("Rate limit check passed for IP {}", client_ip);
            }
            Err(_) => {
                warn!("Rate limit exceeded for IP {}", client_ip);
                let mut response = Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Full::new(bytes::Bytes::from(json!({
                        "error": {
                            "code": -32005,
                            "message": "Rate limit exceeded. Please try again later.",
                            "request_id": &request_id
                        }
                    }).to_string())))
                    .context("Failed to build rate limit response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
                );
                response.headers_mut().insert(
                    "Retry-After",
                    hyper::header::HeaderValue::from_static("60")
                );
                add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
                return Ok(response);
            }
        }
    }

    // Health check endpoint
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
            })
        };

        let mut response = Response::new(Full::new(bytes::Bytes::from(health_status.to_string())));
        response.headers_mut().insert(
            "X-Request-ID",
            request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
        );
        add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
        return Ok(response);
    }

    // Handle CORS preflight (OPTIONS) request
    if req.method() == hyper::Method::OPTIONS {
        debug!("CORS preflight request");
        let mut response = Response::new(Full::new(bytes::Bytes::new()));
        response.headers_mut().insert(
            "X-Request-ID",
            request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
        );
        add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
        return Ok(response);
    }

    // Validate Content-Type header for POST requests
    if req.method() == hyper::Method::POST {
        let content_type = req.headers()
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
                    .body(Full::new(bytes::Bytes::from("Content-Type must be application/json")))
                    .context("Failed to build response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
                );
                add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
                return Ok(response);
            }
            None => {
                warn!("Missing Content-Type header");
                let mut response = Response::builder()
                    .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .body(Full::new(bytes::Bytes::from("Content-Type header required")))
                    .context("Failed to build response")?;
                response.headers_mut().insert(
                    "X-Request-ID",
                    request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
                );
                add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
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
                        request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
                    );
                    add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
                    return Ok(response);
                }
            }
        }
    }

    // Read request body
    let whole_body = req.collect().await
        .context("Failed to read request body")?
        .to_bytes();

    let str_body = String::from_utf8(whole_body.to_vec())
        .context("Request body is not valid UTF-8")?;

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
                data: None
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
            bytes::Bytes::from(json!({
                "error": {
                    "code": err.code,
                    "message": err.message,
                    "request_id": &request_id
                }
            }).to_string())
        }
    };

    let mut response = Response::new(Full::new(body_bytes));
    response.headers_mut().insert(
        "X-Request-ID",
        request_id.parse().unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown"))
    );
    add_cors_and_security_headers(&mut response, &server_config.cors_origins, request_origin);
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    info!("Starting Rust Verusd RPC Server");

    // Load configuration from file and environment variables
    // Environment variables must be prefixed with VERUS_RPC_ and use uppercase
    // Example: VERUS_RPC_RPC_URL, VERUS_RPC_SERVER_PORT
    let settings = config::Config::builder()
        .add_source(config::File::with_name("Conf"))
        .add_source(
            config::Environment::with_prefix("VERUS_RPC")
                .separator("_")
        )
        .build()
        .context("Failed to load configuration")?;

    // Read and validate configuration
    let url = settings.get_string("rpc_url")
        .context("Failed to read 'rpc_url' from configuration")?
        .trim()
        .to_string();
    let user = settings.get_string("rpc_user")
        .context("Failed to read 'rpc_user' from configuration")?
        .trim()
        .to_string();
    let password = settings.get_string("rpc_password")
        .context("Failed to read 'rpc_password' from configuration")?
        .trim()
        .to_string();
    let port = settings.get_int("server_port")
        .context("Failed to read 'server_port' from configuration")?;
    let server_addr_str = settings.get_string("server_addr")
        .context("Failed to read 'server_addr' from configuration")?
        .trim()
        .to_string();

    // Validate RPC URL format
    if url.is_empty() {
        return Err(anyhow!("rpc_url cannot be empty"));
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(anyhow!("rpc_url must start with http:// or https://"));
    }

    // Validate credentials are not empty
    if user.is_empty() {
        return Err(anyhow!("rpc_user cannot be empty"));
    }
    if password.is_empty() {
        return Err(anyhow!("rpc_password cannot be empty"));
    }

    // Validate port range
    if !(1..=65535).contains(&port) {
        return Err(anyhow!("Invalid server_port: must be between 1 and 65535"));
    }

    // Validate server address is not empty
    if server_addr_str.is_empty() {
        return Err(anyhow!("server_addr cannot be empty"));
    }

    // Parse and validate server address
    let server_addr = server_addr_str.parse::<IpAddr>()
        .context("Invalid server_addr: must be a valid IP address")?;

    // Read request timeout from configuration with default
    let timeout_secs = settings.get_int("request_timeout")
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT as i64);
    let timeout = Duration::from_secs(timeout_secs as u64);

    // Read rate limiting configuration
    let rate_limit_per_minute = settings.get_int("rate_limit_per_minute")
        .unwrap_or(DEFAULT_RATE_LIMIT_PER_MINUTE as i64) as u32;
    let rate_limit_burst = settings.get_int("rate_limit_burst")
        .unwrap_or(DEFAULT_RATE_LIMIT_BURST as i64) as u32;

    // Read API keys configuration
    let api_keys = settings.get_string("api_keys").ok()
        .map(|keys_str| {
            keys_str.split(',')
                .map(|k| k.trim().to_string())
                .filter(|k| !k.is_empty())
                .collect::<HashSet<String>>()
        })
        .filter(|keys: &HashSet<String>| !keys.is_empty());

    // Read CORS origins configuration
    let cors_origins = settings.get_string("cors_allowed_origins")
        .ok()
        .map(|origins_str| {
            origins_str.split(',')
                .map(|o| o.trim().to_string())
                .filter(|o| !o.is_empty())
                .collect::<Vec<String>>()
        })
        .unwrap_or_else(|| vec!["*".to_string()]);

    let server_config = Arc::new(ServerConfig {
        api_keys: api_keys.clone(),
        cors_origins: cors_origins.clone(),
    });

    // Read TLS configuration
    let tls_cert_path = settings.get_string("tls_cert_path").ok();
    let tls_key_path = settings.get_string("tls_key_path").ok();

    let tls_acceptor = match (tls_cert_path, tls_key_path) {
        (Some(cert), Some(key)) => {
            info!("Loading TLS configuration...");
            let tls_config = load_tls_config(&cert, &key)
                .context("Failed to load TLS configuration")?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(tls_config))))
        }
        (Some(_), None) => {
            return Err(anyhow!("tls_cert_path provided but tls_key_path is missing"));
        }
        (None, Some(_)) => {
            return Err(anyhow!("tls_key_path provided but tls_cert_path is missing"));
        }
        (None, None) => None,
    };

    let addr = SocketAddr::from((server_addr, port as u16));

    info!("Connecting to RPC server at {}", url);
    info!("Request timeout set to {} seconds", timeout_secs);

    // Create and validate RPC client
    let rpc = Arc::new(
        VerusRPC::new(&url, &user, &password, timeout)
            .context("Failed to create RPC client")?
    );

    // Create rate limiter
    let quota = Quota::per_minute(
        NonZeroU32::new(rate_limit_per_minute)
            .context("rate_limit_per_minute must be greater than 0")?
    ).allow_burst(
        NonZeroU32::new(rate_limit_burst)
            .context("rate_limit_burst must be greater than 0")?
    );
    let rate_limiter = Arc::new(RateLimiter::dashmap(quota));

    let protocol = if tls_acceptor.is_some() { "https" } else { "http" };

    info!("Server listening on {}", addr);
    info!("Health check available at {}://{}/health", protocol, addr);
    info!("Rate limiting: {} requests/minute with burst of {}", rate_limit_per_minute, rate_limit_burst);

    if tls_acceptor.is_some() {
        info!("TLS/HTTPS: ENABLED");
    } else {
        warn!("TLS/HTTPS: DISABLED - using plain HTTP (not recommended for production)");
    }

    if api_keys.is_some() {
        info!("API key authentication: ENABLED");
    } else {
        warn!("API key authentication: DISABLED (not recommended for production)");
    }

    if cors_origins.len() == 1 && cors_origins[0] == "*" {
        warn!("CORS: Allowing all origins (not recommended for production)");
    } else {
        info!("CORS: Allowing origins: {:?}", cors_origins);
    }

    // Create TCP listener
    let listener = TcpListener::bind(addr).await
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
            let rate_limiter_clone = Arc::clone(&rate_limiter);
            let server_config_clone = Arc::clone(&server_config);
            let client_ip = remote_addr.ip();

            // Handle connection with or without TLS
            if let Some(ref acceptor) = tls_acceptor {
                // HTTPS connection
                let acceptor_clone = Arc::clone(acceptor);
                tokio::task::spawn(async move {
                    match acceptor_clone.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            if let Err(err) = http1::Builder::new()
                                .serve_connection(io, service_fn(move |req| {
                                    let rpc = Arc::clone(&rpc_clone);
                                    let rate_limiter = Arc::clone(&rate_limiter_clone);
                                    let server_config = Arc::clone(&server_config_clone);
                                    async move {
                                        handle_req(req, rpc, rate_limiter, client_ip, server_config).await
                                    }
                                }))
                                .await
                            {
                                error!("Error serving HTTPS connection from {}: {:?}", remote_addr, err);
                            }
                        }
                        Err(err) => {
                            error!("TLS handshake failed from {}: {:?}", remote_addr, err);
                        }
                    }
                });
            } else {
                // HTTP connection
                tokio::task::spawn(async move {
                    let io = TokioIo::new(stream);
                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req| {
                            let rpc = Arc::clone(&rpc_clone);
                            let rate_limiter = Arc::clone(&rate_limiter_clone);
                            let server_config = Arc::clone(&server_config_clone);
                            async move {
                                handle_req(req, rpc, rate_limiter, client_ip, server_config).await
                            }
                        }))
                        .await
                    {
                        error!("Error serving HTTP connection from {}: {:?}", remote_addr, err);
                    }
                });
            }
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
