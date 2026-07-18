use std::{
    convert::Infallible,
    future::{self, Future},
};

use hb46pp::client::{
    Client, DiscoveryAnswer, DiscoveryResolver, Transport, TransportRequest, TransportResponse,
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
    let _client = Client::new(FakeResolver, FakeTransport);
}
