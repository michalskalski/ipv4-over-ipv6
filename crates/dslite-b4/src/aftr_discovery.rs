//! Discovers an AFTR and retains protocol results in memory.
//!
//! A retained result may contain an AFTR, a negative result, or a retryable
//! error. Every retained result has a next attempt time. Reconciliation may
//! still run before that time, but it reuses the retained result instead of
//! starting another provisioning request.

use std::{fmt, time::Instant};

#[cfg(feature = "hb46pp")]
use std::time::Duration;

#[cfg(feature = "hb46pp")]
use anyhow::Context;

use crate::config::{AftrAddress, DiscoveryConfig, DiscoveryMethod};

/// The current result of automatic AFTR discovery.
#[derive(Debug, Clone)]
pub enum DiscoveryState {
    /// An AFTR is available from automatic discovery.
    Available(AftrAddress),
    /// Automatic discovery authoritatively reported no service.
    NoService,
    /// Automatic discovery cannot provide an authoritative result.
    Unavailable,
}

/// An automatic discovery result and its next protocol deadline.
///
/// A no-service or unavailable result may be retained. In that case,
/// `next_attempt_at` prevents unrelated wake events from starting another
/// provisioning attempt early.
#[derive(Debug)]
pub struct DiscoveryOutput {
    state: DiscoveryState,
    next_attempt_at: Option<Instant>,
}

impl DiscoveryOutput {
    fn new(state: DiscoveryState, next_attempt_at: Option<Instant>) -> Self {
        Self {
            state,
            next_attempt_at,
        }
    }

    /// Returns the discovery state and selected time for the next attempt.
    pub fn into_parts(self) -> (DiscoveryState, Option<Instant>) {
        (self.state, self.next_attempt_at)
    }
}

#[cfg(feature = "hb46pp")]
/// A discovery result retained until another provisioning attempt is allowed.
#[derive(Debug)]
struct RetainedDiscovery {
    state: DiscoveryState,
    next_attempt_at: Instant,
}

#[cfg(feature = "hb46pp")]
impl RetainedDiscovery {
    fn is_active(&self, now: Instant) -> bool {
        now < self.next_attempt_at
    }

    fn output(&self) -> DiscoveryOutput {
        DiscoveryOutput::new(self.state.clone(), Some(self.next_attempt_at))
    }
}

/// Runs configured AFTR discovery and retains state between attempts.
pub struct DiscoveryRuntime {
    kind: DiscoveryRuntimeKind,
}

enum DiscoveryRuntimeKind {
    None,
    #[cfg(feature = "hb46pp")]
    Hb46pp(Box<Hb46ppRuntime>),
}

#[cfg(feature = "hb46pp")]
struct Hb46ppRuntime {
    request: hb46pp::ProvisioningRequest,
    client: hb46pp::client::DefaultClient,
    retained: Option<RetainedDiscovery>,
}

#[cfg(feature = "hb46pp")]
impl Hb46ppRuntime {
    async fn discover_aftr(&mut self) -> anyhow::Result<DiscoveryOutput> {
        let now = Instant::now();
        if let Some(retained) = self.retained.as_ref() {
            if retained.is_active(now) {
                tracing::debug!(
                    next_attempt_in_secs =
                        retained.next_attempt_at.duration_since(now).as_secs(),
                    state = ?retained.state,
                    "reusing retained HB46PP discovery result"
                );
                return Ok(retained.output());
            }

            self.retained = None;
        }

        tracing::debug!("starting HB46PP provisioning attempt");
        let outcome = match self.client.provision(&self.request).await {
            Ok(outcome) => outcome,
            Err(error) => return self.handle_provisioning_error(error),
        };
        let next_attempt_after = choose_next_attempt_delay(outcome.next_attempt_window());

        match outcome {
            hb46pp::client::ProvisioningOutcome::Provisioned(response) => {
                self.apply_response(response, next_attempt_after)
            }
            hb46pp::client::ProvisioningOutcome::NotFound => {
                tracing::debug!(
                    next_attempt_after_secs = next_attempt_after.as_secs(),
                    "HB46PP bootstrap record not found"
                );

                // Retain the authoritative no-service result so network change hints
                // do not bypass the protocol retry window.
                Ok(self.retain(DiscoveryState::NoService, next_attempt_after))
            }
        }
    }

    fn handle_provisioning_error(
        &mut self,
        error: hb46pp::client::ClientError,
    ) -> anyhow::Result<DiscoveryOutput> {
        let Some(action) = error.retry_action() else {
            return Err(error).context("HB46PP provisioning failed");
        };

        let retry_after = choose_next_attempt_delay(action.window());

        let state = match action {
            hb46pp::client::RetryAction::DisableMigration(_) => DiscoveryState::NoService,
            hb46pp::client::RetryAction::PreserveMigration(_) => DiscoveryState::Unavailable,
            _ => DiscoveryState::Unavailable,
        };

        tracing::warn!(
            error = %error,
            discovery_state = ?state,
            retry_after_secs = retry_after.as_secs(),
            "HB46PP provisioning failed, retry deferred"
        );

        Ok(self.retain(state, retry_after))
    }

    fn apply_response(
        &mut self,
        response: hb46pp::client::ProvisioningResponse,
        next_attempt_after: Duration,
    ) -> anyhow::Result<DiscoveryOutput> {
        tracing::debug!(
            ttl_secs = ?response.data().ttl().map(|ttl| ttl.as_secs()),
            cache_control = ?response.cache_control(),
            may_persist = response.may_persist(),
            "HB46PP provisioning response received"
        );

        let aftr = crate::hb46pp::dslite_aftr(response.data())
            .context("invalid DS-Lite provisioning offer")?;

        if let Some(token) = response.data().token().cloned() {
            self.request.set_token(Some(token));
        }

        let state = match aftr {
            Some(address) => {
                tracing::debug!(
                    source = "hb46pp",
                    aftr = ?address,
                    "AFTR source selected"
                );

                DiscoveryState::Available(address)
            }
            None => {
                tracing::debug!("HB46PP response has no active DS-Lite offer");

                DiscoveryState::NoService
            }
        };

        tracing::debug!(
            refresh_after_secs = next_attempt_after.as_secs(),
            "HB46PP provisioning result retained in memory"
        );

        // Cache-Control no-store prohibits persistence, not retaining the
        // provisioning result in memory.
        Ok(self.retain(state, next_attempt_after))
    }

    fn retain(&mut self, state: DiscoveryState, next_attempt_after: Duration) -> DiscoveryOutput {
        let retained = RetainedDiscovery {
            state,
            next_attempt_at: Instant::now() + next_attempt_after,
        };
        let output = retained.output();

        self.retained = Some(retained);
        output
    }
}

impl fmt::Debug for DiscoveryRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DiscoveryRuntimeKind::None => f.write_str("None"),
            #[cfg(feature = "hb46pp")]
            DiscoveryRuntimeKind::Hb46pp(runtime) => {
                let Hb46ppRuntime {
                    request, retained, ..
                } = runtime.as_ref();

                f.debug_struct("Hb46pp")
                    .field("request", request)
                    .field("retained", retained)
                    .finish_non_exhaustive()
            }
        }
    }
}

impl DiscoveryRuntime {
    /// Validates that the selected discovery method is available and configured.
    pub fn validate_config(config: &DiscoveryConfig) -> anyhow::Result<()> {
        match config.method {
            DiscoveryMethod::None => Ok(()),
            DiscoveryMethod::Hb46pp => Self::validate_hb46pp_config(config),
        }
    }

    /// Creates discovery state from the validated daemon configuration.
    pub fn from_config(config: &DiscoveryConfig) -> anyhow::Result<Self> {
        match config.method {
            DiscoveryMethod::None => Ok(Self {
                kind: DiscoveryRuntimeKind::None,
            }),
            DiscoveryMethod::Hb46pp => Self::hb46pp(config),
        }
    }

    #[cfg(feature = "hb46pp")]
    fn validate_hb46pp_config(config: &DiscoveryConfig) -> anyhow::Result<()> {
        crate::hb46pp::provisioning_request(config).context("invalid HB46PP configuration")?;

        Ok(())
    }

    #[cfg(not(feature = "hb46pp"))]
    fn validate_hb46pp_config(_: &DiscoveryConfig) -> anyhow::Result<()> {
        anyhow::bail!("HB46PP support is not included in this build")
    }

    #[cfg(feature = "hb46pp")]
    fn hb46pp(config: &DiscoveryConfig) -> anyhow::Result<Self> {
        let request =
            crate::hb46pp::provisioning_request(config).context("invalid HB46PP configuration")?;
        let client = hb46pp::client::DefaultClient::try_new()
            .context("creating the default HB46PP client")?;

        Ok(Self {
            kind: DiscoveryRuntimeKind::Hb46pp(Box::new(Hb46ppRuntime {
                request,
                client,
                retained: None,
            })),
        })
    }

    #[cfg(not(feature = "hb46pp"))]
    fn hb46pp(_: &DiscoveryConfig) -> anyhow::Result<Self> {
        anyhow::bail!("HB46PP support is not included in this build")
    }

    /// Discovers an AFTR or returns a retained result that is still active.
    pub async fn discover_aftr(&mut self) -> anyhow::Result<DiscoveryOutput> {
        match &mut self.kind {
            DiscoveryRuntimeKind::None => {
                tracing::debug!("automatic AFTR discovery is disabled");
                Ok(DiscoveryOutput::new(DiscoveryState::Unavailable, None))
            }
            #[cfg(feature = "hb46pp")]
            DiscoveryRuntimeKind::Hb46pp(runtime) => runtime.discover_aftr().await,
        }
    }
}

#[cfg(feature = "hb46pp")]
fn choose_next_attempt_delay(window: hb46pp::client::NextAttemptWindow) -> Duration {
    let seconds = rand::random_range(window.min().as_secs()..=window.max().as_secs());

    Duration::from_secs(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb46pp_discovery_config() -> DiscoveryConfig {
        DiscoveryConfig {
            method: DiscoveryMethod::Hb46pp,
            vendor_id: "000000".into(),
            product: "dslite-b4".into(),
        }
    }

    #[cfg(feature = "hb46pp")]
    #[test]
    fn prepares_hb46pp_discovery_when_support_is_compiled_in() {
        let runtime = DiscoveryRuntime::from_config(&hb46pp_discovery_config()).unwrap();

        assert!(matches!(runtime.kind, DiscoveryRuntimeKind::Hb46pp(_)));
    }

    #[cfg(feature = "hb46pp")]
    #[test]
    fn rejects_invalid_identity_when_hb46pp_is_selected() {
        let mut config = hb46pp_discovery_config();
        config.vendor_id = "invalid".into();

        let result = DiscoveryRuntime::validate_config(&config);

        assert!(result.is_err(), "result: {result:?}");
    }

    #[cfg(feature = "hb46pp")]
    #[test]
    fn chooses_delay_within_next_attempt_window() {
        let window = hb46pp::client::ProvisioningOutcome::NotFound.next_attempt_window();
        let delay = choose_next_attempt_delay(window);

        assert!(
            (window.min()..=window.max()).contains(&delay),
            "delay: {delay:?}"
        );
    }

    #[cfg(feature = "hb46pp")]
    #[test]
    fn retained_discovery_expires_at_next_attempt_deadline() {
        let now = Instant::now();
        let retained = RetainedDiscovery {
            state: DiscoveryState::Unavailable,
            next_attempt_at: now + Duration::from_secs(1),
        };

        assert!(retained.is_active(now));
        assert!(!retained.is_active(retained.next_attempt_at));
    }

    #[cfg(not(feature = "hb46pp"))]
    #[test]
    fn rejects_hb46pp_when_support_is_not_compiled_in() {
        let result = DiscoveryRuntime::validate_config(&hb46pp_discovery_config());

        let error = result.unwrap_err();
        assert_eq!(
            error.to_string(),
            "HB46PP support is not included in this build"
        );
    }

    #[cfg(feature = "hb46pp")]
    #[test]
    fn malformed_bootstrap_disables_discovered_service() {
        let runtime = DiscoveryRuntime::from_config(&hb46pp_discovery_config()).unwrap();
        let DiscoveryRuntimeKind::Hb46pp(mut runtime) = runtime.kind else {
            unreachable!();
        };

        let output = runtime
            .handle_provisioning_error(hb46pp::client::ClientError::UnexpectedRecordCount(2))
            .unwrap();
        let (state, next_attempt_at) = output.into_parts();

        assert!(matches!(state, DiscoveryState::NoService));
        assert!(next_attempt_at.is_some());
    }

    #[cfg(feature = "hb46pp")]
    #[test]
    fn temporary_resolver_failure_keeps_discovered_service() {
        let runtime = DiscoveryRuntime::from_config(&hb46pp_discovery_config()).unwrap();
        let DiscoveryRuntimeKind::Hb46pp(mut runtime) = runtime.kind else {
            unreachable!();
        };

        let output = runtime
            .handle_provisioning_error(hb46pp::client::ClientError::Resolver(Box::new(
                std::io::Error::other("DNS lookup failed"),
            )))
            .unwrap();
        let (state, next_attempt_at) = output.into_parts();

        assert!(matches!(state, DiscoveryState::Unavailable));
        assert!(next_attempt_at.is_some());
    }
}
