//! Chooses when the daemon next reconciles desired and observed state.
//!
//! Reconciliation may resume because of a timer, network change, or signal.
//! A wake does not always permit a new provisioning request.
//!
//! Desired state computation supplies a scheduling hint. The scheduler wakes
//! at whichever comes first, the health interval or the time requested by the
//! hint. Generic failures use the daemon retry policy. Protocol results use
//! their selected next attempt time.
//!
//! HB46PP discovery retains its next attempt time and checks it on every
//! reconciliation pass. This prevents network events and signals from causing
//! an early protocol retry while still allowing the daemon to observe and
//! reconcile tunnel state.

use std::time::{Duration, Instant};

/// A scheduling constraint produced while computing desired state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WakeHint {
    /// No wake is required before the periodic health check.
    None,

    /// Reconcile no later than this protocol deadline.
    Deadline(Instant),

    /// Reconcile using the daemon retry policy.
    GenericRetry,
}

/// The constraint that selected the next wake time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WakeReason {
    /// The periodic health check occurs first.
    Health,

    /// A discovery deadline occurs first.
    Discovery,

    /// A retry from the daemon policy occurs first.
    GenericRetry,
}

/// The selected wake time and the constraint that selected it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ScheduledWake {
    /// The monotonic time when reconciliation should resume.
    pub(super) at: Instant,

    /// Why this wake time was selected.
    pub(super) reason: WakeReason,
}

/// Selects the earliest wake requested by health and retry policy.
///
/// Generic retries use exponential backoff from one second through thirty
/// seconds. The health interval remains an upper bound on the wait.
pub(super) fn schedule_next_wake(
    now: Instant,
    health_interval: Duration,
    hint: WakeHint,
    retry_attempt: u64,
) -> ScheduledWake {
    let health = ScheduledWake {
        at: now + health_interval,
        reason: WakeReason::Health,
    };

    match hint {
        WakeHint::None => health,
        WakeHint::Deadline(at) => earliest(
            health,
            ScheduledWake {
                at,
                reason: WakeReason::Discovery,
            },
        ),
        WakeHint::GenericRetry => {
            let retry_seconds = (1_u64 << retry_attempt.min(5)).min(30);
            let retry = ScheduledWake {
                at: now + Duration::from_secs(retry_seconds),
                reason: WakeReason::GenericRetry,
            };
            earliest(health, retry)
        }
    }
}

fn earliest(current: ScheduledWake, candidate: ScheduledWake) -> ScheduledWake {
    if candidate.at < current.at {
        candidate
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_earliest_wake() {
        let now = Instant::now();

        let cases = [
            (
                "health without retry",
                Duration::from_secs(60),
                WakeHint::None,
                0,
                Duration::from_secs(60),
                WakeReason::Health,
            ),
            (
                "generic retry before health",
                Duration::from_secs(60),
                WakeHint::GenericRetry,
                2,
                Duration::from_secs(4),
                WakeReason::GenericRetry,
            ),
            (
                "health before generic retry",
                Duration::from_secs(2),
                WakeHint::GenericRetry,
                3,
                Duration::from_secs(2),
                WakeReason::Health,
            ),
            (
                "generic retry capped at thirty seconds",
                Duration::from_secs(60),
                WakeHint::GenericRetry,
                10,
                Duration::from_secs(30),
                WakeReason::GenericRetry,
            ),
            (
                "discovery deadline before health",
                Duration::from_secs(60),
                WakeHint::Deadline(now + Duration::from_secs(30)),
                0,
                Duration::from_secs(30),
                WakeReason::Discovery,
            ),
            (
                "health before discovery deadline",
                Duration::from_secs(60),
                WakeHint::Deadline(now + Duration::from_secs(120)),
                0,
                Duration::from_secs(60),
                WakeReason::Health,
            ),
        ];

        for (name, health_interval, hint, attempt, expected_delay, expected_reason) in cases {
            let scheduled = schedule_next_wake(now, health_interval, hint, attempt);

            assert_eq!(
                scheduled,
                ScheduledWake {
                    at: now + expected_delay,
                    reason: expected_reason,
                },
                "{name}",
            );
        }
    }
}
