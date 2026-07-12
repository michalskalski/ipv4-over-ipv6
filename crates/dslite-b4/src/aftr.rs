use std::{
    net::Ipv6Addr,
    time::{Duration, Instant},
};

pub struct AftrSelector {
    missing_since: Option<Instant>,
}

impl AftrSelector {
    pub fn new() -> Self {
        Self {
            missing_since: None,
        }
    }

    pub fn select(
        &mut self,
        candidates: &[Ipv6Addr],
        current: Option<Ipv6Addr>,
        missing_grace: Duration,
        now: Instant,
    ) -> Option<Ipv6Addr> {
        let Some(first_candidate) = candidates.first().copied() else {
            self.missing_since = None;
            return None;
        };

        let Some(current) = current else {
            self.missing_since = None;
            return Some(first_candidate);
        };

        if candidates.contains(&current) {
            self.missing_since = None;
            return Some(current);
        }

        let missing_since = match self.missing_since {
            Some(missing_since) => missing_since,
            None => {
                self.missing_since = Some(now);
                tracing::debug!(
                    current_remote_v6 = %current,
                    candidate_remote_v6 = %first_candidate,
                    grace_secs = missing_grace.as_secs(),
                    "current AFTR missing from DNS, keeping it during grace period"
                );
                return Some(current);
            }
        };

        if now.duration_since(missing_since) < missing_grace {
            tracing::debug!(
                current_remote_v6 = %current,
                candidate_remote_v6 = %first_candidate,
                missing_secs = now.duration_since(missing_since).as_secs(),
                grace_secs = missing_grace.as_secs(),
                "current AFTR still missing from DNS, keeping it during grace period"
            );
            return Some(current);
        }

        self.missing_since = None;
        tracing::info!(
            previous_remote_v6 = %current,
            selected_remote_v6 = %first_candidate,
            missing_secs = now.duration_since(missing_since).as_secs(),
            grace_secs = missing_grace.as_secs(),
            "current AFTR missing from DNS beyond grace period, selecting new AFTR"
        );
        Some(first_candidate)
    }
}

impl Default for AftrSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)
    }

    #[test]
    fn selects_first_candidate_without_current_aftr() {
        let mut selector = AftrSelector::new();
        let now = Instant::now();

        let selected = selector.select(&[addr(1), addr(2)], None, Duration::from_secs(600), now);

        assert_eq!(selected, Some(addr(1)));
        assert_eq!(selector.missing_since, None);
    }

    #[test]
    fn keeps_current_aftr_when_still_in_candidates() {
        let mut selector = AftrSelector {
            missing_since: Some(Instant::now()),
        };
        let now = Instant::now();

        let selected = selector.select(
            &[addr(1), addr(2)],
            Some(addr(2)),
            Duration::from_secs(600),
            now,
        );

        assert_eq!(selected, Some(addr(2)));
        assert_eq!(selector.missing_since, None);
    }

    #[test]
    fn starts_grace_when_current_aftr_first_goes_missing() {
        let mut selector = AftrSelector::new();
        let now = Instant::now();

        let selected = selector.select(&[addr(1)], Some(addr(2)), Duration::from_secs(600), now);

        assert_eq!(selected, Some(addr(2)));
        assert_eq!(selector.missing_since, Some(now));
    }

    #[test]
    fn keeps_current_aftr_while_missing_within_grace() {
        let started = Instant::now();
        let mut selector = AftrSelector {
            missing_since: Some(started),
        };

        let selected = selector.select(
            &[addr(1)],
            Some(addr(2)),
            Duration::from_secs(600),
            started + Duration::from_secs(599),
        );

        assert_eq!(selected, Some(addr(2)));
        assert_eq!(selector.missing_since, Some(started));
    }

    #[test]
    fn selects_first_candidate_after_grace_expires() {
        let started = Instant::now();
        let mut selector = AftrSelector {
            missing_since: Some(started),
        };

        let selected = selector.select(
            &[addr(1)],
            Some(addr(2)),
            Duration::from_secs(600),
            started + Duration::from_secs(600),
        );

        assert_eq!(selected, Some(addr(1)));
        assert_eq!(selector.missing_since, None);
    }

    #[test]
    fn empty_candidates_clear_missing_state_and_select_nothing() {
        let mut selector = AftrSelector {
            missing_since: Some(Instant::now()),
        };
        let now = Instant::now();

        let selected = selector.select(&[], Some(addr(2)), Duration::from_secs(600), now);

        assert_eq!(selected, None);
        assert_eq!(selector.missing_since, None);
    }
}
