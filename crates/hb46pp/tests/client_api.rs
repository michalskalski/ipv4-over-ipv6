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
use hb46pp::{
    Capability, Credentials, FirmwareVersion, MapEVersion, MapEVersionError, Product,
    ProvisioningData, ProvisioningOffer, ProvisioningRequest, Token, TunnelEndpoint, VendorId,
};

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

#[test]
fn downstream_crates_can_construct_and_update_requests() {
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let credentials =
        Credentials::unrestricted("user".to_string(), "password".to_string()).unwrap();
    let mut request = ProvisioningRequest::new(
        "000000".parse::<VendorId>().unwrap(),
        "example-router".parse::<Product>().unwrap(),
        "1_0_0".parse::<FirmwareVersion>().unwrap(),
        vec![Capability::DsLite],
    )
    .unwrap()
    .with_credentials(credentials);

    assert_eq!(request.credentials().unwrap().user(), "user");
    assert!(request.token().is_none());

    request.set_token(Some(TOKEN.parse::<Token>().unwrap()));
    assert_eq!(request.token().map(Token::as_str), Some(TOKEN));
}

#[test]
fn downstream_crates_can_use_typed_and_raw_offers() {
    let data = ProvisioningData::parse(
        r#"{
            "enabler_name":"example",
            "order":["dslite"],
            "dslite":{"aftr":"2001:db8::1","future_member":{"enabled":true}}
        }"#,
    )
    .unwrap();

    let selected = data.select(&[Capability::DsLite]).unwrap();
    let ProvisioningOffer::DsLite(parameters) = selected else {
        panic!("expected DS-Lite parameters");
    };
    assert_eq!(
        parameters.aftr(),
        &TunnelEndpoint::Ipv6("2001:db8::1".parse().unwrap())
    );
    assert_eq!(
        data.raw_offer(Capability::DsLite).unwrap()["future_member"]["enabled"],
        true
    );
    assert_eq!(
        data.dslite().unwrap().aftr(),
        &TunnelEndpoint::Ipv6("2001:db8::1".parse().unwrap())
    );
}

#[test]
fn downstream_crates_can_use_non_exhaustive_map_e_versions() {
    fn name(version: MapEVersion) -> &'static str {
        match version {
            MapEVersion::Draft03 => "draft-03",
            MapEVersion::Rfc7597 => "rfc-7597",
            _ => "future",
        }
    }

    assert_eq!(name(MapEVersion::Draft03), "draft-03");
    assert_eq!(
        "2".parse::<MapEVersion>(),
        Err(MapEVersionError::UnsupportedValue("2".to_string()))
    );
}
