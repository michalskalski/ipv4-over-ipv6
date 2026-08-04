#![cfg(feature = "client")]

#[cfg(any(feature = "default-client", feature = "default-transport"))]
use std::time::Duration;
use std::{
    convert::Infallible,
    future::{self, Future},
};

#[cfg(feature = "default-resolver")]
use hb46pp::client::DefaultDiscoveryResolver;
#[cfg(feature = "default-transport")]
use hb46pp::client::DefaultTransport;
use hb46pp::client::{
    Client, ClientError, DiscoveryAnswer, DiscoveryResolver, ProvisioningAuthenticationPolicy,
    ProvisioningOutcome, RetryAction, Transport, TransportRequest, TransportResponse,
};
#[cfg(feature = "default-client")]
use hb46pp::client::{DefaultClient, DefaultClientBuilder, DefaultClientError};

struct FakeResolver;

impl DiscoveryResolver for FakeResolver {
    type Error = Infallible;

    fn lookup_txt(
        &self,
        _name: &str,
    ) -> impl Future<Output = Result<DiscoveryAnswer, Self::Error>> {
        future::ready(Ok(DiscoveryAnswer::NotFound))
    }
}

struct FakeTransport;

impl Transport for FakeTransport {
    type Error = Infallible;

    fn send_once(
        &self,
        _request: TransportRequest,
    ) -> impl Future<Output = Result<TransportResponse, Self::Error>> {
        future::ready(Ok(TransportResponse::new(
            200,
            None,
            None,
            br#"{"order":[]}"#.to_vec(),
        )))
    }
}

#[test]
fn downstream_crates_can_implement_transport() {
    fn accepts_transport(_: &impl Transport) {}

    accepts_transport(&FakeTransport);
}

#[test]
fn downstream_crates_can_implement_discovery_resolver() {
    fn accepts_resolver(_: &impl DiscoveryResolver) {}

    accepts_resolver(&FakeResolver);
}

#[test]
fn downstream_crates_can_construct_client() {
    let _client = Client::new(FakeResolver, FakeTransport)
        .with_authentication_policy(ProvisioningAuthenticationPolicy::AllowUnauthenticated);
}

#[test]
fn downstream_crates_can_inspect_next_attempt_window() {
    let window = ProvisioningOutcome::NotFound.next_attempt_window();

    assert!(window.min() <= window.max());
}

#[cfg(feature = "default-client")]
#[test]
fn downstream_crates_can_construct_the_default_client() {
    let constructor: fn() -> Result<DefaultClient, DefaultClientError> = DefaultClient::try_new;
    let builder_constructor: fn() -> DefaultClientBuilder = DefaultClient::builder;

    let _ = constructor;
    let _ = builder_constructor()
        .request_timeout(Duration::from_secs(10))
        .authentication_policy(ProvisioningAuthenticationPolicy::AllowUnauthenticated)
        .max_redirects(2);
}

#[cfg(feature = "default-resolver")]
#[test]
fn downstream_crates_can_use_the_default_resolver() {
    fn accepts_resolver_type<R: DiscoveryResolver>() {}

    accepts_resolver_type::<DefaultDiscoveryResolver>();
}

#[cfg(feature = "default-transport")]
#[test]
fn downstream_crates_can_use_the_default_transport() {
    fn accepts_transport_type<T: Transport>() {}

    accepts_transport_type::<DefaultTransport>();

    let timeout_constructor: fn(Duration) -> Result<DefaultTransport, reqwest::Error> =
        DefaultTransport::new_with_request_timeout;
    let _ = timeout_constructor;
}

#[test]
fn downstream_crates_can_inspect_retry_actions() {
    let action = ClientError::UnexpectedRecordCount(2)
        .retry_action()
        .unwrap();

    assert!(matches!(&action, RetryAction::DisableMigration(_)));

    let window = action.window();
    assert!(window.min() <= window.max());
}
