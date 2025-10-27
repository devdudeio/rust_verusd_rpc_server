# Contributing to Rust Verusd RPC Server

Thank you for your interest in contributing to Rust Verusd RPC Server! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security](#security)

## Code of Conduct

This project follows a code of conduct that promotes a welcoming and inclusive environment. Please be respectful and professional in all interactions.

## Getting Started

### Prerequisites

- Rust 1.70 or later
- Git
- Docker (optional, for container testing)

### Setting Up the Development Environment

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/rust_verusd_rpc_server.git
   cd rust_verusd_rpc_server
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/devdudeio/rust_verusd_rpc_server.git
   ```

4. Create a configuration file:
   ```bash
   cp Conf.toml.example Conf.toml
   # Edit Conf.toml with your local Verus RPC settings
   ```

5. Build and test:
   ```bash
   cargo build
   cargo test
   ```

## Development Workflow

1. **Create a new branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards below

3. **Test your changes**:
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt
   ```

4. **Commit your changes** following the commit message guidelines

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a Pull Request** on GitHub

## Coding Standards

### Rust Code Style

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `cargo fmt` to format your code before committing
- Run `cargo clippy` and address all warnings
- Add documentation comments for public functions and modules
- Use meaningful variable and function names

### Code Quality

- **DRY (Don't Repeat Yourself)**: Extract common logic into reusable functions
- **Single Responsibility**: Functions should do one thing well
- **Error Handling**: Use `Result` and `?` operator for proper error propagation
- **Type Safety**: Leverage Rust's type system for compile-time guarantees
- **Documentation**: Add rustdoc comments for all public APIs

### Example

```rust
/// Validates an API key against the configured set of valid keys.
///
/// This function uses constant-time comparison to prevent timing attacks.
///
/// # Arguments
///
/// * `provided_key` - The API key to validate
/// * `valid_keys` - Set of valid API keys
///
/// # Returns
///
/// * `true` if the key is valid
/// * `false` otherwise
fn validate_api_key(provided_key: &str, valid_keys: &HashSet<String>) -> bool {
    // Implementation
}
```

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run integration tests only
cargo test --test integration_test
```

### Writing Tests

- Add unit tests for all new functionality
- Integration tests should cover end-to-end scenarios
- Use descriptive test names that explain what is being tested
- Test both success and failure cases
- Mock external dependencies when appropriate

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_with_valid_input() {
        // Arrange
        let input = "valid";

        // Act
        let result = function_under_test(input);

        // Assert
        assert_eq!(result, expected_value);
    }

    #[test]
    fn test_function_with_invalid_input() {
        let input = "invalid";
        let result = function_under_test(input);
        assert!(result.is_err());
    }
}
```

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification for commit messages.

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that don't affect code meaning (formatting, etc.)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Performance improvement
- **test**: Adding or updating tests
- **chore**: Changes to build process or auxiliary tools

### Examples

```
feat: add rate limiting headers to responses

Add X-RateLimit-Limit and X-RateLimit-Remaining headers to all responses
to inform clients about their rate limit status.
```

```
fix: prevent timing attack in API key validation

Use constant-time comparison for API key validation to prevent timing
attacks that could leak information about valid API keys.
```

```
docs: update README with Kubernetes deployment examples

Add comprehensive Kubernetes deployment guide with:
- Deployment manifest
- Service configuration
- Health and readiness probes
```

## Pull Request Process

1. **Update documentation**: If your changes affect user-facing behavior, update the README and relevant documentation

2. **Add tests**: All new features must include tests

3. **Update CHANGELOG**: Add your changes to the Unreleased section of CHANGELOG.md

4. **Ensure CI passes**: All tests, linting, and formatting checks must pass

5. **Request review**: Tag maintainers for review

6. **Address feedback**: Respond to review comments and make requested changes

7. **Squash commits** (if requested): Keep history clean with meaningful commit messages

### Pull Request Checklist

- [ ] Code follows the project's style guidelines
- [ ] All tests pass (`cargo test`)
- [ ] No clippy warnings (`cargo clippy -- -D warnings`)
- [ ] Code is formatted (`cargo fmt`)
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Commit messages follow conventional commits format

## Security

### Reporting Security Issues

If you discover a security vulnerability, please **DO NOT** open a public issue. Instead:

1. Email the maintainers directly
2. Provide a detailed description of the vulnerability
3. Include steps to reproduce if possible
4. Allow time for the issue to be fixed before public disclosure

### Security Best Practices

When contributing code:

- Never commit secrets, API keys, or credentials
- Validate all user input
- Use constant-time operations for security-sensitive comparisons
- Follow the principle of least privilege
- Document security implications of your changes

## Questions?

If you have questions:

- Check existing issues and discussions
- Open a new issue with the `question` label
- Join community discussions

Thank you for contributing to Rust Verusd RPC Server! 🎉
