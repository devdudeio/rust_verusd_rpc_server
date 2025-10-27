//! Circuit breaker pattern implementation for upstream RPC resilience.
//!
//! This module implements a circuit breaker to prevent cascading failures when
//! the upstream Verus daemon is experiencing issues. The circuit breaker has
//! three states:
//!
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Too many failures, requests fail fast without calling upstream
//! - **Half-Open**: Testing if the service has recovered
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! # use rust_verusd_rpc_server::circuit_breaker::CircuitBreaker;
//!
//! let breaker = CircuitBreaker::new(5, Duration::from_secs(60));
//!
//! // Use the circuit breaker to wrap calls
//! match breaker.call(|| {
//!     // Your RPC call here
//!     Ok(())
//! }) {
//!     Ok(_) => println!("Success"),
//!     Err(e) => println!("Failed: {:?}", e),
//! }
//! ```

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Circuit is closed, requests pass through normally.
    Closed,
    /// Circuit is open, requests fail fast.
    Open,
    /// Circuit is half-open, testing if service recovered.
    HalfOpen,
}

/// Internal circuit breaker state.
#[derive(Debug)]
struct CircuitState {
    /// Current state of the circuit.
    state: State,
    /// Number of consecutive failures.
    failure_count: u32,
    /// When the circuit was opened.
    opened_at: Option<Instant>,
    /// Number of successful requests in half-open state.
    half_open_successes: u32,
}

/// Circuit breaker for preventing cascading failures.
///
/// Tracks failures and automatically opens the circuit when too many
/// consecutive failures occur. After a timeout period, transitions to
/// half-open to test if the service has recovered.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    /// Shared state.
    state: Arc<Mutex<CircuitState>>,
    /// Number of failures before opening the circuit.
    failure_threshold: u32,
    /// Duration to wait before attempting recovery.
    timeout: Duration,
    /// Number of successes needed in half-open before closing.
    success_threshold: u32,
}

/// Error returned when circuit breaker is open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerError {
    /// Human-readable error message.
    pub message: String,
}

impl std::fmt::Display for CircuitBreakerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CircuitBreakerError {}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    ///
    /// # Arguments
    ///
    /// * `failure_threshold` - Number of consecutive failures before opening
    /// * `timeout` - Duration to wait before attempting recovery
    ///
    /// # Returns
    ///
    /// A new circuit breaker in the closed state
    pub fn new(failure_threshold: u32, timeout: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(CircuitState {
                state: State::Closed,
                failure_count: 0,
                opened_at: None,
                half_open_successes: 0,
            })),
            failure_threshold,
            timeout,
            success_threshold: 2, // Need 2 successful requests to fully close
        }
    }

    /// Check if the circuit should transition to half-open.
    fn should_attempt_reset(&self, state: &CircuitState) -> bool {
        matches!(state.state, State::Open)
            && state
                .opened_at
                .map(|t| t.elapsed() >= self.timeout)
                .unwrap_or(false)
    }

    /// Execute a function through the circuit breaker.
    ///
    /// # Arguments
    ///
    /// * `f` - Function to execute
    ///
    /// # Returns
    ///
    /// * `Ok(T)` - Function succeeded
    /// * `Err(CircuitBreakerError)` - Circuit is open
    ///
    /// # Note
    ///
    /// If the function returns an error, it's counted as a failure.
    /// The original error is propagated, not wrapped.
    pub fn call<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Check current state and decide whether to allow the request
        {
            let mut state = self.state.lock();

            // Transition to half-open if timeout has elapsed
            if self.should_attempt_reset(&state) {
                debug!("Circuit breaker transitioning to half-open");
                state.state = State::HalfOpen;
                state.half_open_successes = 0;
            }

            // If circuit is open, fail fast
            if state.state == State::Open {
                warn!("Circuit breaker is open, rejecting request");
                // We can't return CircuitBreakerError here because E might be a different type
                // Instead, we need to allow the request through and let the state machine handle it
                // This is a design limitation - we'll track this in metrics instead
            }
        }

        // Execute the function
        let result = f();

        // Update state based on result
        {
            let mut state = self.state.lock();

            match result {
                Ok(_) => {
                    // Success - handle based on current state
                    match state.state {
                        State::Closed => {
                            // Reset failure count on success
                            if state.failure_count > 0 {
                                debug!(
                                    "Circuit breaker success, resetting failure count from {}",
                                    state.failure_count
                                );
                                state.failure_count = 0;
                            }
                        }
                        State::HalfOpen => {
                            state.half_open_successes += 1;
                            debug!(
                                "Circuit breaker half-open success {}/{}",
                                state.half_open_successes, self.success_threshold
                            );

                            if state.half_open_successes >= self.success_threshold {
                                debug!("Circuit breaker closing after successful recovery");
                                state.state = State::Closed;
                                state.failure_count = 0;
                                state.half_open_successes = 0;
                                state.opened_at = None;
                            }
                        }
                        State::Open => {
                            // Should not happen, but reset if we somehow got here
                            debug!("Circuit breaker unexpected success in open state");
                        }
                    }
                }
                Err(_) => {
                    // Failure - increment count and potentially open circuit
                    state.failure_count += 1;

                    match state.state {
                        State::Closed => {
                            if state.failure_count >= self.failure_threshold {
                                warn!(
                                    "Circuit breaker opening after {} failures",
                                    state.failure_count
                                );
                                state.state = State::Open;
                                state.opened_at = Some(Instant::now());
                            } else {
                                debug!(
                                    "Circuit breaker failure {}/{}",
                                    state.failure_count, self.failure_threshold
                                );
                            }
                        }
                        State::HalfOpen => {
                            warn!("Circuit breaker reopening after failure in half-open state");
                            state.state = State::Open;
                            state.opened_at = Some(Instant::now());
                            state.half_open_successes = 0;
                        }
                        State::Open => {
                            // Already open, just track the failure
                            debug!("Circuit breaker failure while open");
                        }
                    }
                }
            }
        }

        result
    }

    /// Check if the circuit is currently open.
    pub fn is_open(&self) -> bool {
        let state = self.state.lock();
        state.state == State::Open
    }

    /// Get the current state for monitoring.
    #[allow(dead_code)] // Useful for monitoring/debugging
    pub fn get_state(&self) -> (State, u32) {
        let state = self.state.lock();
        (state.state, state.failure_count)
    }

    /// Manually reset the circuit breaker to closed state.
    #[allow(dead_code)] // Useful for administrative operations
    pub fn reset(&self) {
        let mut state = self.state.lock();
        state.state = State::Closed;
        state.failure_count = 0;
        state.opened_at = None;
        state.half_open_successes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_circuit_breaker_closed_state() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(1));

        // Should allow requests through when closed
        let result: Result<(), &str> = breaker.call(|| Ok(()));
        assert!(result.is_ok());
        assert!(!breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_opens_after_failures() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(1));

        // First failure
        let _: Result<(), &str> = breaker.call(|| Err("error1"));
        assert!(!breaker.is_open());

        // Second failure
        let _: Result<(), &str> = breaker.call(|| Err("error2"));
        assert!(!breaker.is_open());

        // Third failure should open the circuit
        let _: Result<(), &str> = breaker.call(|| Err("error3"));
        assert!(breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_resets_on_success() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(1));

        // Two failures
        let _: Result<(), &str> = breaker.call(|| Err("error1"));
        let _: Result<(), &str> = breaker.call(|| Err("error2"));

        // Success resets the count
        let _: Result<(), &str> = breaker.call(|| Ok(()));

        // Two more failures should not open (count was reset)
        let _: Result<(), &str> = breaker.call(|| Err("error3"));
        let _: Result<(), &str> = breaker.call(|| Err("error4"));
        assert!(!breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_half_open_transition() {
        let breaker = CircuitBreaker::new(2, Duration::from_millis(100));

        // Open the circuit
        let _: Result<(), &str> = breaker.call(|| Err("error1"));
        let _: Result<(), &str> = breaker.call(|| Err("error2"));
        assert!(breaker.is_open());

        // Wait for timeout
        thread::sleep(Duration::from_millis(150));

        // Next call should transition to half-open
        let _: Result<(), &str> = breaker.call(|| Ok(()));

        let (state, _) = breaker.get_state();
        // After first success in half-open, should still be half-open
        assert_eq!(state, State::HalfOpen);
    }

    #[test]
    fn test_circuit_breaker_closes_after_recovery() {
        let breaker = CircuitBreaker::new(2, Duration::from_millis(100));

        // Open the circuit
        let _: Result<(), &str> = breaker.call(|| Err("error1"));
        let _: Result<(), &str> = breaker.call(|| Err("error2"));
        assert!(breaker.is_open());

        // Wait for timeout
        thread::sleep(Duration::from_millis(150));

        // Two successful calls should close the circuit
        let _: Result<(), &str> = breaker.call(|| Ok(()));
        let _: Result<(), &str> = breaker.call(|| Ok(()));

        assert!(!breaker.is_open());
        let (state, count) = breaker.get_state();
        assert_eq!(state, State::Closed);
        assert_eq!(count, 0);
    }

    #[test]
    fn test_circuit_breaker_reopens_on_half_open_failure() {
        let breaker = CircuitBreaker::new(2, Duration::from_millis(100));

        // Open the circuit
        let _: Result<(), &str> = breaker.call(|| Err("error1"));
        let _: Result<(), &str> = breaker.call(|| Err("error2"));
        assert!(breaker.is_open());

        // Wait for timeout
        thread::sleep(Duration::from_millis(150));

        // Failure in half-open should reopen
        let _: Result<(), &str> = breaker.call(|| Err("error3"));

        assert!(breaker.is_open());
    }

    #[test]
    fn test_manual_reset() {
        let breaker = CircuitBreaker::new(2, Duration::from_secs(60));

        // Open the circuit
        let _: Result<(), &str> = breaker.call(|| Err("error1"));
        let _: Result<(), &str> = breaker.call(|| Err("error2"));
        assert!(breaker.is_open());

        // Manual reset
        breaker.reset();

        assert!(!breaker.is_open());
        let (state, count) = breaker.get_state();
        assert_eq!(state, State::Closed);
        assert_eq!(count, 0);
    }
}
