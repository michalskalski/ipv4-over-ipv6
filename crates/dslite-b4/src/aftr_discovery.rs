use std::fmt;
#[cfg(feature = "hb46pp")]
use std::time::{Duration, Instant};

#[cfg(feature = "hb46pp")]
use anyhow::Context;

use crate::config::{AftrAddress, DiscoveryConfig, DiscoveryMethod};

#[cfg(feature = "hb46pp")]
#[derive(Debug)]
struct ActiveProvisioning {
    aftr: Option<AftrAddress>,
    refresh_at: Instant,
}

#[cfg(feature = "hb46pp")]
impl ActiveProvisioning {
    fn is_fresh(&self, now: Instant) -> bool {
        now < self.refresh_at
    }
}

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
    active: Option<ActiveProvisioning>,
}

#[cfg(feature = "hb46pp")]
impl Hb46ppRuntime {
    async fn discover_aftr(&mut self) -> anyhow::Result<Option<AftrAddress>> {
        let now = Instant::now();
        if let Some(cached) = self.active.as_ref()
            && cached.is_fresh(now)
        {
            tracing::debug!(
                refresh_in_secs = cached.refresh_at.duration_since(now).as_secs(),
                aftr = ?cached.aftr,
                "reusing active HB46PP provisioning result"
            );
            return Ok(cached.aftr.clone());
        }

        tracing::debug!("starting HB46PP provisioning attempt");
        let outcome = self
            .client
            .provision(&self.request)
            .await
            .context("HB46PP provisioning failed")?;
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

                // Retain negative discovery so network-change hints do not bypass
                // the protocol retry window.
                self.store_active(None, next_attempt_after);
                Ok(None)
            }
        }
    }

    fn apply_response(
        &mut self,
        response: hb46pp::client::ProvisioningResponse,
        next_attempt_after: Duration,
    ) -> anyhow::Result<Option<AftrAddress>> {
        tracing::debug!(
            ttl_secs = ?response.data().ttl().map(|ttl| ttl.as_secs()),
            cache_control = ?response.cache_control(),
            may_persist = response.may_persist(),
            "HB46PP provisioning response received"
        );

        let aftr = crate::hb46pp::dslite_aftr(response.data())
            .context("invalid DS-Lite provisioning offer")?;

        match &aftr {
            Some(address) => tracing::debug!(
                source = "hb46pp",
                aftr = ?address,
                "AFTR source selected"
            ),
            None => tracing::debug!("HB46PP response has no active DS-Lite offer"),
        }

        tracing::debug!(
            refresh_after_secs = next_attempt_after.as_secs(),
            "HB46PP provisioning result retained in memory"
        );

        // Cache-Control no-store prohibits persistence, not retaining the
        // active provisioning state in memory.
        self.store_active(aftr.clone(), next_attempt_after);
        Ok(aftr)
    }

    fn store_active(&mut self, aftr: Option<AftrAddress>, refresh_after: Duration) {
        self.active = Some(ActiveProvisioning {
            aftr,
            refresh_at: Instant::now() + refresh_after,
        });
    }
}

impl fmt::Debug for DiscoveryRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DiscoveryRuntimeKind::None => f.write_str("None"),
            #[cfg(feature = "hb46pp")]
            DiscoveryRuntimeKind::Hb46pp(runtime) => {
                let Hb46ppRuntime {
                    request, active, ..
                } = runtime.as_ref();

                f.debug_struct("Hb46pp")
                    .field("request", request)
                    .field("active", active)
                    .finish_non_exhaustive()
            }
        }
    }
}

impl DiscoveryRuntime {
    pub fn validate_config(config: &DiscoveryConfig) -> anyhow::Result<()> {
        match config.method {
            DiscoveryMethod::None => Ok(()),
            DiscoveryMethod::Hb46pp => Self::validate_hb46pp_config(config),
        }
    }

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
                active: None,
            })),
        })
    }

    #[cfg(not(feature = "hb46pp"))]
    fn hb46pp(_: &DiscoveryConfig) -> anyhow::Result<Self> {
        anyhow::bail!("HB46PP support is not included in this build")
    }

    pub async fn discover_aftr(&mut self) -> anyhow::Result<Option<AftrAddress>> {
        match &mut self.kind {
            DiscoveryRuntimeKind::None => {
                tracing::debug!("automatic AFTR discovery is disabled");
                Ok(None)
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
    fn active_provisioning_expires_at_refresh_deadline() {
        let now = Instant::now();
        let active = ActiveProvisioning {
            aftr: None,
            refresh_at: now + Duration::from_secs(1),
        };

        assert!(active.is_fresh(now));
        assert!(!active.is_fresh(active.refresh_at));
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
}
