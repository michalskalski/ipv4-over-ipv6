#![cfg(feature = "client")]

use std::{
    convert::Infallible,
    future::{self, Future},
};

#[cfg(feature = "default-resolver")]
use hb46pp::client::DefaultDiscoveryResolver;
#[cfg(feature = "default-transport")]
use hb46pp::client::DefaultTransport;
use hb46pp::client::{
    Client, DiscoveryAnswer, DiscoveryResolver, Transport, TransportRequest, TransportResponse,
};
#[cfg(feature = "default-client")]
use hb46pp::client::{DefaultClient, DefaultClientError};

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
    let _client = Client::new(FakeResolver, FakeTransport);
}

#[cfg(feature = "default-client")]
#[test]
fn downstream_crates_can_construct_the_default_client() {
    let constructor: fn() -> Result<DefaultClient, DefaultClientError> = DefaultClient::try_new;

    let _ = constructor;
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
}
