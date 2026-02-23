/// Path: PanicMode/scr/detector/circuit_breaker.rs
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;
use tokio::time::timeout;
use anyhow::Result;
use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use futures::FutureExt;

// State encoding
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl From<u8> for CircuitState {
    fn from(val: u8) -> Self {
        match val {
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

impl From<CircuitState> for u8 {
    fn from(val: CircuitState) -> Self {
        match val {
            CircuitState::Closed => STATE_CLOSED,
            CircuitState::Open => STATE_OPEN,
            CircuitState::HalfOpen => STATE_HALF_OPEN,
        }
    }
}

pub struct CircuitBreaker {
    // Single source of truth
    atomic_state: Arc<AtomicU8>,

    // Details
    details: Arc<Mutex<BreakerDetails>>,
    
    // Lock-free concurrency
    active_requests: Arc<AtomicUsize>,
    
    // HalfOpen guard
    half_open_active: Arc<AtomicBool>,
    
    // Config
    max_failures: u32,
    failure_window: Duration,
    base_open_duration: Duration,
    request_timeout: Duration,
    max_concurrent: usize,
    
    // Emergency
    kill_switch: Arc<AtomicBool>,
    
    // Instance seed
    instance_seed: u64,
}

struct BreakerDetails {
    failure_times: VecDeque<Instant>,
    opened_at: Option<Instant>,
    consecutive_opens: u32,
}

impl CircuitBreaker {
    pub fn new(
        max_failures: u32,
        failure_window: Duration,
        base_open_duration: Duration,
    ) -> Self {
        let time_seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        let ptr_seed = (&time_seed as *const u64) as u64;
        let instance_seed = time_seed.wrapping_add(ptr_seed);
        
        Self {
            atomic_state: Arc::new(AtomicU8::new(STATE_CLOSED)),
            details: Arc::new(Mutex::new(BreakerDetails {
                failure_times: VecDeque::new(),
                opened_at: None,
                consecutive_opens: 0,
            })),
            active_requests: Arc::new(AtomicUsize::new(0)),
            half_open_active: Arc::new(AtomicBool::new(false)),
            max_failures,
            failure_window,
            base_open_duration,
            request_timeout: Duration::from_secs(10),
            max_concurrent: 10.max(1), // Minimum 1!
            kill_switch: Arc::new(AtomicBool::new(false)),
            instance_seed,
        }
    }
    
    pub fn with_concurrency_limit(mut self, limit: usize) -> Self {
        self.max_concurrent = limit.max(1); // Minimum 1!
        self
    }
    
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
    
    pub fn emergency_shutdown(&self) {
        tracing::error!("🚨 EMERGENCY SHUTDOWN");
        self.kill_switch.store(true, Ordering::Release);
        self.atomic_state.store(STATE_OPEN, Ordering::Release);
        self.half_open_active.store(false, Ordering::Release);
    }
    
    pub fn is_emergency_shutdown(&self) -> bool {
        self.kill_switch.load(Ordering::Acquire)
    }
    
    fn get_state(&self) -> CircuitState {
        self.atomic_state.load(Ordering::Acquire).into()
    }
    
    /// Main entry point.
    pub async fn call<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        // Emergency
        if self.is_emergency_shutdown() {
            anyhow::bail!("Emergency shutdown");
        }
        
        // State check
        let current_state = self.get_state();
        
        if current_state == CircuitState::Open {
            if !self.try_transition_open_to_half_open().await {
                anyhow::bail!("Circuit breaker is OPEN");
            }
        }
        
        // Concurrency (saturating)
        let prev = self.active_requests.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max_concurrent {
            // Rollback
            self.active_requests.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |x| Some(x.saturating_sub(1))
            ).ok();
            anyhow::bail!("Concurrency limit ({}/{})", prev + 1, self.max_concurrent);
        }
        
        // RAII guard
        let _concurrency_guard = ConcurrencyGuard {
            counter: self.active_requests.clone(),
        };
        
        // HalfOpen guard
        let _half_open_guard = if self.get_state() == CircuitState::HalfOpen {
            if !self.half_open_active.compare_exchange(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            ).is_ok() {
                anyhow::bail!("HalfOpen test in progress");
            }
            Some(HalfOpenGuard {
                active: self.half_open_active.clone(),
            })
        } else {
            None
        };
        
        // Execute
        let result = self.execute_with_protection(f).await;
        
        // State transition
        match &result {
            Ok(_) => {
                self.on_success_sync().await;
            }
            Err(_) => {
                self.on_failure_sync().await;
            }
        }
        
        result
    }
    
    async fn execute_with_protection<F, Fut, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let future = AssertUnwindSafe(async move {
            timeout(self.request_timeout, f()).await
        });
        
        match future.catch_unwind().await {
            // Success
            Ok(Ok(Ok(value))) => Ok(value),

            // Business error from f() (NOT a timeout!)
            Ok(Ok(Err(e))) => Err(e),
            
            // TIMEOUT (Elapsed)
            Ok(Err(_elapsed)) => {
                tracing::error!("⏱️  Request timed out after {:?}", self.request_timeout);
                anyhow::bail!("Request timed out after {:?}", self.request_timeout)
            }
            
            // PANIC
            Err(_) => {
                tracing::error!("🚨 Request PANICKED");
                anyhow::bail!("Request panicked")
            }
        }
    }
    
    /// Atomic Open → HalfOpen transition with timeout check under lock.
    async fn try_transition_open_to_half_open(&self) -> bool {
        // CAS first (optimistic transition)
        let cas_result = self.atomic_state.compare_exchange(
            STATE_OPEN,
            STATE_HALF_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        
        if cas_result.is_err() {
            // No longer Open — someone else got there first
            return false;
        }

        // CAS succeeded — now verify the timeout
        let mut details = self.details.lock().await;
        
        let should_be_half_open = if let Some(opened_at) = details.opened_at {
            let duration = self.calculate_open_duration(details.consecutive_opens);
            Instant::now().duration_since(opened_at) >= duration
        } else {
            false
        };
        
        if should_be_half_open {
            // All good — stay in HalfOpen
            tracing::info!("⚡ Open -> HalfOpen (timeout expired)");
            true
        } else {
            // Timeout has NOT expired — revert to Open
            self.atomic_state.store(STATE_OPEN, Ordering::Release);
            false
        }
    }
    
    async fn on_success_sync(&self) {
        let current = self.get_state();
        
        if current == CircuitState::HalfOpen {
            let mut details = self.details.lock().await;
            details.failure_times.clear();
            details.opened_at = None;
            details.consecutive_opens = 0;
            
            self.atomic_state.store(STATE_CLOSED, Ordering::Release);
            tracing::info!("⚡ HalfOpen -> Closed");
        } else if current == CircuitState::Closed {
            let mut details = self.details.lock().await;
            Self::cleanup_old_failures(&mut details.failure_times, self.failure_window);
        }
    }
    
    async fn on_failure_sync(&self) {
        let now = Instant::now();
        let current = self.get_state();
        
        let mut details = self.details.lock().await;
        
        // Record the failure
        details.failure_times.push_back(now);

        // Strict cap
        while details.failure_times.len() > self.max_failures as usize {
            details.failure_times.pop_front();
        }
        
        Self::cleanup_old_failures(&mut details.failure_times, self.failure_window);
        
        let failure_count = details.failure_times.len();
        
        match current {
            CircuitState::HalfOpen => {
                details.opened_at = Some(now);
                details.consecutive_opens += 1;
                self.atomic_state.store(STATE_OPEN, Ordering::Release);
                tracing::warn!("⚡ HalfOpen -> Open (consecutive: {})", details.consecutive_opens);
            }
            CircuitState::Closed => {
                if failure_count >= self.max_failures as usize {
                    details.opened_at = Some(now);
                    details.consecutive_opens += 1;
                    self.atomic_state.store(STATE_OPEN, Ordering::Release);
                    tracing::error!("⚡ Closed -> Open ({} failures)", failure_count);
                }
            }
            CircuitState::Open => {
                // Already Open — count failures, but do NOT reset opened_at.
                // The timer must run from the moment the breaker first opened;
                // otherwise it would never transition to HalfOpen under sustained errors.
                details.consecutive_opens += 1;
            }
        }
    }
    
    fn cleanup_old_failures(failures: &mut VecDeque<Instant>, window: Duration) {
        let now = Instant::now();
        
        while let Some(&oldest) = failures.front() {
            match now.checked_duration_since(oldest) {
                Some(elapsed) if elapsed > window => {
                    failures.pop_front();
                }
                None => {
                    tracing::warn!("⚠️  Instant overflow");
                    failures.clear();
                    break;
                }
                _ => break,
            }
        }
    }
    
    fn calculate_open_duration(&self, consecutive_opens: u32) -> Duration {
        let base_millis = self.base_open_duration.as_millis() as u64;
        
        if base_millis == 0 {
            return Duration::from_millis(1);
        }
        
        let multiplier = 2u64.saturating_pow(consecutive_opens.min(10));
        let backoff_millis = base_millis.saturating_mul(multiplier);
        
        // XorShift
        let mut seed = self.instance_seed.wrapping_add(consecutive_opens as u64);
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        
        let jitter_range = backoff_millis / 4;
        let jitter = if jitter_range > 0 {
            seed % jitter_range
        } else {
            0
        };
        
        let final_millis = backoff_millis.saturating_add(jitter);
        Duration::from_millis(final_millis.min(5 * 60 * 1000))
    }
    
    pub async fn stats(&self) -> CircuitBreakerStats {
        let details = self.details.lock().await;
        
        CircuitBreakerStats {
            state: self.get_state(),
            failure_count: details.failure_times.len(),
            consecutive_opens: details.consecutive_opens,
            active_requests: self.active_requests.load(Ordering::Acquire),
            is_half_open_active: self.half_open_active.load(Ordering::Acquire),
            is_emergency_shutdown: self.is_emergency_shutdown(),
        }
    }
}

struct ConcurrencyGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        self.counter.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |x| Some(x.saturating_sub(1))
        ).ok();
    }
}

struct HalfOpenGuard {
    active: Arc<AtomicBool>,
}

impl Drop for HalfOpenGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: usize,
    pub consecutive_opens: u32,
    pub active_requests: usize,
    pub is_half_open_active: bool,
    pub is_emergency_shutdown: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timeout_vs_business_error() {
        let cb = Arc::new(
            CircuitBreaker::new(2, Duration::from_secs(10), Duration::from_secs(1))
                .with_timeout(Duration::from_millis(100))
        );
        
        // Business error (NOT a timeout)
        let result1 = cb.call(|| async {
            Err::<(), _>(anyhow::anyhow!("business error"))
        }).await;
        assert!(result1.is_err());
        assert!(result1.unwrap_err().to_string().contains("business"));
        
        // Real timeout
        let result2 = cb.call(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<(), anyhow::Error>(())
        }).await;
        assert!(result2.is_err());
        assert!(result2.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_cas_then_lock_transition() {
        let cb = Arc::new(
            CircuitBreaker::new(2, Duration::from_secs(10), Duration::from_millis(50))
        );
        
        // Open circuit
        for _ in 0..2 {
            let _ = cb.call(|| async { Err::<(), _>(anyhow::anyhow!("fail")) }).await;
        }
        
        // Do NOT wait for timeout
        let result = cb.try_transition_open_to_half_open().await;

        // CAS will succeed, but timeout has not expired — reverts to Open
        assert!(!result);
        assert_eq!(cb.get_state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_min_concurrency_limit() {
        let cb = CircuitBreaker::new(10, Duration::from_secs(10), Duration::from_secs(1))
            .with_concurrency_limit(0); // Attempt to set 0

        // Must be at least 1
        assert_eq!(cb.max_concurrent, 1);
    }

    #[tokio::test]
    async fn test_race_open_failure_and_transition() {
        let cb = Arc::new(
            CircuitBreaker::new(2, Duration::from_secs(10), Duration::from_millis(50))
        );
        
        // Open
        for _ in 0..2 {
            let _ = cb.call(|| async { Err::<(), _>(anyhow::anyhow!("fail")) }).await;
        }
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Concurrent: transition and failure
        let cb1 = cb.clone();
        let cb2 = cb.clone();
        
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { cb1.try_transition_open_to_half_open().await }),
            tokio::spawn(async move {
                cb2.on_failure_sync().await;
            })
        );
        
        // Must not be state corruption
        let stats = cb.stats().await;
        assert!(stats.state == CircuitState::Open || stats.state == CircuitState::HalfOpen);
    }
}