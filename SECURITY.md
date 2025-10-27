# Security Policy

## Supported Versions

We take security seriously and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT open a public issue for security vulnerabilities.**

If you discover a security vulnerability in this project, please report it privately using one of these methods:

### GitHub Security Advisories (Preferred)

1. Go to the [Security tab](https://github.com/devdudeio/rust_verusd_rpc_server/security)
2. Click "Report a vulnerability"
3. Fill out the security advisory form

### Email

Alternatively, you can email security concerns to the project maintainers. Check the repository for contact information.

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: What an attacker could achieve
- **Steps to Reproduce**: Detailed steps to reproduce the vulnerability
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have a fix or mitigation in mind (optional)
- **Your Contact Info**: So we can follow up with you

## Response Timeline

- **Initial Response**: Within 48 hours of report
- **Status Update**: Within 7 days with severity assessment
- **Fix Timeline**: Depends on severity
  - Critical: Patch within 7 days
  - High: Patch within 14 days
  - Medium: Patch within 30 days
  - Low: Addressed in next release

## Security Update Process

1. **Triage**: We assess the vulnerability and confirm the issue
2. **Fix Development**: We develop and test a fix
3. **Disclosure**: We coordinate disclosure with the reporter
4. **Release**: We release a patched version
5. **Advisory**: We publish a security advisory (if warranted)

## Security Best Practices

When deploying this RPC server in production:

- **Always use HTTPS** via a reverse proxy (Caddy, nginx)
- **Enable API key authentication** with strong, random keys (16+ characters)
- **Use strong RPC credentials** for the upstream Verus daemon (12+ characters)
- **Configure IP access control** to limit access to known networks
- **Run as non-root user** (Docker image does this by default)
- **Keep software updated** to get the latest security patches
- **Monitor audit logs** for suspicious activity
- **Configure rate limiting** appropriately for your use case
- **Review security warnings** on server startup and address them

## Known Security Considerations

### Rate Limiting

- The server implements per-IP rate limiting, but sophisticated attackers may use distributed IPs
- Consider deploying additional DDoS protection at the network level

### Authentication

- API keys are compared using constant-time comparison to prevent timing attacks
- Store API keys securely (use environment variables, not config files in version control)

### Input Validation

- All RPC methods are validated against an allowlist
- Parameters are type-checked but not fully sanitized
- The upstream Verus daemon is trusted to handle malformed requests safely

### Audit Logging

- Audit logs may contain sensitive information
- Ensure proper log retention and access control policies

## Acknowledgments

We appreciate security researchers who responsibly disclose vulnerabilities to us. Contributors who report valid security issues may be acknowledged in our security advisories (with permission).

## Contact

For general security questions (not vulnerability reports), please open a discussion in the [GitHub Discussions](https://github.com/devdudeio/rust_verusd_rpc_server/discussions) section.
