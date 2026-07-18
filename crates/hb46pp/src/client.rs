use url::Url;

use crate::{
    Bootstrap, BootstrapError, ProvisioningRequest, ProvisioningResponse,
    ProvisioningResponseError, ProvisioningUrlError, TlsPolicy,
};
use std::{error::Error, future::Future, str::Utf8Error};

const DISCOVERY_NAME: &str = "4over6.info";
const DEFAULT_MAX_REDIRECTS: usize = 5;

/// An outbound HB46PP provisioning request for a transport to send.
///
/// The transport must connect to the endpoint over IPv6 and apply the
/// bootstrap record's TLS policy.
pub struct TransportRequest {
    endpoint: Url,
    tls_policy: TlsPolicy,
}

impl TransportRequest {
    /// Creates a provisioning request for an endpoint discovered through
    /// HB46PP bootstrap.
    pub fn new(endpoint: Url, tls_policy: TlsPolicy) -> Self {
        Self {
            endpoint,
            tls_policy,
        }
    }

    /// Returns the provisioning endpoint.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Returns the certificate-validation policy from the bootstrap record.
    pub fn tls_policy(&self) -> TlsPolicy {
        self.tls_policy
    }
}

/// An HTTP response returned by a provisioning transport.
///
/// The response owns its body and the HB46PP relevant headers needed for
/// response classification and cache handling.
pub struct TransportResponse {
    status: u16,
    location: Option<String>,
    cache_control: Option<String>,
    body: Vec<u8>,
}

impl TransportResponse {
    /// Creates a response from an HTTP status, selected headers, and body.
    pub fn new(
        status: u16,
        location: Option<String>,
        cache_control: Option<String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            location,
            cache_control,
            body,
        }
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Returns the `Location` header value, when present.
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// Returns the `Cache-Control` header value, when present.
    pub fn cache_control(&self) -> Option<&str> {
        self.cache_control.as_deref()
    }

    /// Returns the complete response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// The result of looking up the HB46PP bootstrap discovery record.
#[derive(Debug, PartialEq, Eq)]
pub enum DiscoveryAnswer {
    /// Complete TXT resource records.
    ///
    /// Each string represents one resource record after its DNS character-string
    /// fragments have been joined in wire order.
    Records(Vec<String>),
    /// No bootstrap record exists because the lookup returned NXDOMAIN or NODATA.
    NotFound,
}

/// Resolves TXT records used for HB46PP bootstrap discovery.
///
/// This trait is limited to the protocol's discovery record. Resolving the
/// provisioning endpoint hostname remains the transport's responsibility.
pub trait DiscoveryResolver: Send + Sync {
    /// The resolver-specific error returned when a TXT lookup fails.
    type Error: Error + Send + Sync + 'static;

    /// Looks up the TXT records for an HB46PP discovery name.
    ///
    /// Implementations must return [`DiscoveryAnswer::NotFound`] for NXDOMAIN
    /// and NODATA. Other resolver failures must be returned as `Err`.
    /// Character-string fragments belonging to one TXT resource record must
    /// be joined before returning [`DiscoveryAnswer::Records`].
    fn lookup_txt(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<DiscoveryAnswer, Self::Error>> + Send;
}

/// Sends HTTP provisioning requests for the HB46PP client.
///
/// Implementations resolve the provisioning endpoint, connect over IPv6, and
/// apply the request's TLS policy. They return the received HTTP status,
/// relevant headers, and body without applying HB46PP redirect or retry
/// rules as those remain the client's responsibility. Implementations must not
/// follow redirects automatically.
pub trait Transport: Send + Sync {
    /// The transport-specific error returned when sending a request fails.
    type Error: Error + Send + Sync + 'static;

    /// Sends one provisioning request.
    fn send_once(
        &self,
        request: TransportRequest,
    ) -> impl Future<Output = Result<TransportResponse, Self::Error>> + Send;
}

/// An error encountered while processing an HB46PP redirect response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RedirectError {
    /// The response did not include the target endpoint.
    #[error("redirect response is missing the Location header")]
    MissingLocation,
    /// The target could not be resolved against the current endpoint.
    #[error("invalid redirect Location header")]
    InvalidLocation(#[source] url::ParseError),
    /// The resolved target did not use HTTP or HTTPS.
    #[error("unsupported redirect URL scheme: {0}")]
    UnsupportedScheme(String),
    /// An HTTP redirect would violate the bootstrap certificate policy.
    #[error("certificate validation policy requires HTTPS redirects")]
    RequiresHttps,
    /// The response exceeded the client's redirect limit.
    #[error("too many redirects")]
    TooManyRedirects,
}

/// An error encountered while running the HB46PP client flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The discovery resolver could not complete the TXT lookup.
    #[error("bootstrap TXT lookup failed")]
    Resolver(#[source] Box<dyn Error + Send + Sync + 'static>),
    /// Discovery returned a number of TXT records that HB46PP does not permit.
    #[error("expected one bootstrap TXT record, received {0}")]
    UnexpectedRecordCount(usize),
    /// The discovered TXT record was not a valid HB46PP bootstrap record.
    #[error("invalid bootstrap TXT record")]
    Bootstrap(#[source] BootstrapError),
    /// The validated bootstrap and provisioning parameters could not produce
    /// a permitted request URL.
    #[error("failed to construct provisioning URL")]
    ProvisioningUrl(#[source] ProvisioningUrlError),
    /// The transport could not complete a provisioning request.
    #[error("provisioning request failed")]
    Transport(#[source] Box<dyn Error + Send + Sync + 'static>),
    /// The successful HTTP response body was not valid UTF-8.
    #[error("server response is not a proper UTF-8 text")]
    ResponseEncoding(#[source] Utf8Error),
    /// The successful HTTP response body was not valid HB46PP provisioning data.
    #[error("unable to parse provisioning response")]
    ProvisioningResponse(#[source] ProvisioningResponseError),
    /// The server returned an invalid or disallowed redirect.
    #[error("failed to follow redirect")]
    Redirect(#[source] RedirectError),
    /// The server returned an HTTP status not handled as an HB46PP response.
    #[error("server returned unexpected http response code: {0}")]
    UnexpectedResponseStatus(u16),
}

/// An HB46PP provisioning client using caller-provided network adapters.
pub struct Client<R, T> {
    resolver: R,
    transport: T,
    max_redirects: usize,
}

impl<R, T> Client<R, T>
where
    R: DiscoveryResolver,
    T: Transport,
{
    /// Creates a client using the supplied discovery resolver and transport.
    pub fn new(resolver: R, transport: T) -> Self {
        Self {
            resolver,
            transport,
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }

    /// Sets the maximum number of redirects the client will follow.
    ///
    /// A value of zero rejects the first redirect. There is no value that
    /// disables the redirect limit.
    pub fn with_max_redirects(mut self, limit: usize) -> Self {
        self.max_redirects = limit;
        self
    }

    async fn discover_bootstrap(&self) -> Result<Option<Bootstrap>, ClientError> {
        let lookup_result = self
            .resolver
            .lookup_txt(DISCOVERY_NAME)
            .await
            .map_err(|error| ClientError::Resolver(Box::new(error)))?;

        match lookup_result {
            DiscoveryAnswer::NotFound => Ok(None),

            DiscoveryAnswer::Records(records) => {
                let [record] = records.as_slice() else {
                    return Err(ClientError::UnexpectedRecordCount(records.len()));
                };

                Bootstrap::parse(record)
                    .map(Some)
                    .map_err(ClientError::Bootstrap)
            }
        }
    }

    async fn send_request(
        &self,
        endpoint: Url,
        tls_policy: TlsPolicy,
    ) -> Result<TransportResponse, ClientError> {
        let transport_request = TransportRequest::new(endpoint, tls_policy);

        self.transport
            .send_once(transport_request)
            .await
            .map_err(|error| ClientError::Transport(Box::new(error)))
    }

    /// Discovers and requests HB46PP provisioning data.
    ///
    /// Returns `Ok(None)` when the discovery name has no TXT record. A valid
    /// provisioning response is parsed and returned as `Ok(Some(_))`.
    pub async fn provision(
        &self,
        request: &ProvisioningRequest,
    ) -> Result<Option<ProvisioningResponse>, ClientError> {
        let Some(bootstrap) = self.discover_bootstrap().await? else {
            return Ok(None);
        };

        let mut request_url = bootstrap
            .provisioning_url(request)
            .map_err(ClientError::ProvisioningUrl)?;

        let mut redirects_count: usize = 0;
        loop {
            let response = self
                .send_request(request_url.clone(), bootstrap.tls_policy())
                .await?;

            match response.status() {
                200 => {
                    let body = std::str::from_utf8(response.body())
                        .map_err(ClientError::ResponseEncoding)?;

                    return ProvisioningResponse::parse(body)
                        .map(Some)
                        .map_err(ClientError::ProvisioningResponse);
                }
                307 => {
                    if redirects_count >= self.max_redirects {
                        return Err(ClientError::Redirect(RedirectError::TooManyRedirects));
                    }
                    redirects_count += 1;
                    let redirect_target = redirect_endpoint(
                        &request_url,
                        response.location(),
                        bootstrap.tls_policy(),
                    )
                    .map_err(ClientError::Redirect)?;
                    request_url = bootstrap
                        .provisioning_url_for(redirect_target, request)
                        .map_err(ClientError::ProvisioningUrl)?;
                }
                status => return Err(ClientError::UnexpectedResponseStatus(status)),
            }
        }
    }
}

fn redirect_endpoint(
    current_endpoint: &Url,
    location: Option<&str>,
    tls_policy: TlsPolicy,
) -> Result<Url, RedirectError> {
    let location = location.ok_or(RedirectError::MissingLocation)?;

    let endpoint = current_endpoint
        .join(location)
        .map_err(RedirectError::InvalidLocation)?;

    match endpoint.scheme() {
        "https" => {}
        "http" if tls_policy == TlsPolicy::ValidateCertificate => {
            return Err(RedirectError::RequiresHttps);
        }
        "http" => {}
        scheme => return Err(RedirectError::UnsupportedScheme(scheme.to_string())),
    }

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use crate::{Capability, FirmwareVersion, Product, VendorId};

    use super::*;
    use std::{
        convert::Infallible,
        future::{self, Future},
        sync::Mutex,
    };

    struct NotFoundResolver;

    impl DiscoveryResolver for NotFoundResolver {
        type Error = Infallible;

        fn lookup_txt(
            &self,
            _name: &str,
        ) -> impl Future<Output = Result<DiscoveryAnswer, Self::Error>> {
            future::ready(Ok(DiscoveryAnswer::NotFound))
        }
    }

    struct RecordsResolver(&'static [&'static str]);

    impl DiscoveryResolver for RecordsResolver {
        type Error = Infallible;

        fn lookup_txt(
            &self,
            _name: &str,
        ) -> impl Future<Output = Result<DiscoveryAnswer, Self::Error>> {
            let records = self.0.iter().map(|record| (*record).to_string()).collect();
            future::ready(Ok(DiscoveryAnswer::Records(records)))
        }
    }

    struct FailingResolver;

    impl DiscoveryResolver for FailingResolver {
        type Error = std::io::Error;

        fn lookup_txt(
            &self,
            _name: &str,
        ) -> impl Future<Output = Result<DiscoveryAnswer, Self::Error>> {
            future::ready(Err(std::io::Error::other("lookup failed")))
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

    struct SuccessfulTransport;

    impl Transport for SuccessfulTransport {
        type Error = Infallible;

        fn send_once(
            &self,
            request: TransportRequest,
        ) -> impl Future<Output = Result<TransportResponse, Self::Error>> {
            assert_eq!(request.tls_policy(), TlsPolicy::ValidateCertificate);
            assert!(request.endpoint().query_pairs().any(|(key, value)| {
                key == "capability" && value == Capability::DsLite.as_str()
            }));

            future::ready(Ok(TransportResponse::new(
                200,
                None,
                None,
                br#"{
                    "enabler_name": "example",
                    "order": ["dslite"],
                    "dslite": {"aftr": "dslite.example"}
                }"#
                .to_vec(),
            )))
        }
    }

    struct StaticResponseTransport {
        status: u16,
        body: &'static [u8],
    }

    impl Transport for StaticResponseTransport {
        type Error = Infallible;

        fn send_once(
            &self,
            _request: TransportRequest,
        ) -> impl Future<Output = Result<TransportResponse, Self::Error>> {
            future::ready(Ok(TransportResponse::new(
                self.status,
                None,
                None,
                self.body.to_vec(),
            )))
        }
    }

    struct UnexpectedCallTransport;

    impl Transport for UnexpectedCallTransport {
        type Error = std::io::Error;

        fn send_once(
            &self,
            _request: TransportRequest,
        ) -> impl Future<Output = Result<TransportResponse, Self::Error>> {
            future::ready(Err(std::io::Error::other(
                "transport was called unexpectedly",
            )))
        }
    }

    struct RedirectTransport {
        call_count: Mutex<usize>,
        location: &'static str,
        expected_host: &'static str,
        expected_path: &'static str,
    }

    impl RedirectTransport {
        fn new(
            location: &'static str,
            expected_host: &'static str,
            expected_path: &'static str,
        ) -> Self {
            Self {
                call_count: Mutex::new(0),
                location,
                expected_host,
                expected_path,
            }
        }
    }

    impl Transport for RedirectTransport {
        type Error = Infallible;

        fn send_once(
            &self,
            request: TransportRequest,
        ) -> impl Future<Output = Result<TransportResponse, Self::Error>> {
            let call = {
                let mut call_count = self
                    .call_count
                    .lock()
                    .expect("transport mutex should not be poisoned");
                let call = *call_count;
                *call_count += 1;
                call
            };

            match call {
                0 => {
                    assert_eq!(request.endpoint().host_str(), Some("example.com"));

                    future::ready(Ok(TransportResponse::new(
                        307,
                        Some(self.location.to_string()),
                        None,
                        Vec::new(),
                    )))
                }
                1 => {
                    assert_eq!(request.endpoint().host_str(), Some(self.expected_host));
                    assert!(request.endpoint().query_pairs().any(|(key, value)| {
                        key == "capability" && value == Capability::DsLite.as_str()
                    }));
                    assert_eq!(request.tls_policy(), TlsPolicy::ValidateCertificate);
                    assert_eq!(request.endpoint().path(), self.expected_path);

                    future::ready(Ok(TransportResponse::new(
                        200,
                        None,
                        None,
                        br#"{
                    "enabler_name": "example",
                    "order": ["dslite"],
                    "dslite": {"aftr": "dslite.example"}
                }"#
                        .to_vec(),
                    )))
                }
                _ => panic!("transport called more than twice"),
            }
        }
    }

    struct RedirectResponseTransport {
        location: Option<&'static str>,
    }

    impl Transport for RedirectResponseTransport {
        type Error = Infallible;

        fn send_once(
            &self,
            _request: TransportRequest,
        ) -> impl Future<Output = Result<TransportResponse, Self::Error>> {
            future::ready(Ok(TransportResponse::new(
                307,
                self.location.map(str::to_string),
                None,
                Vec::new(),
            )))
        }
    }

    #[tokio::test]
    async fn missing_discovery_record_returns_none() {
        let client = Client::new(NotFoundResolver, FakeTransport);
        let result = client.discover_bootstrap().await;

        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn one_valid_record_returns_some() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            FakeTransport,
        );
        let result = client.discover_bootstrap().await;

        assert!(matches!(result, Ok(Some(_))), "result: {result:?}");
    }

    #[tokio::test]
    async fn zero_records_returns_unexpected_record_count() {
        let client = Client::new(RecordsResolver(&[]), FakeTransport);
        let result = client.discover_bootstrap().await;

        assert!(
            matches!(result, Err(ClientError::UnexpectedRecordCount(0))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn multiple_records_returns_unexpected_record_count() {
        let client = Client::new(RecordsResolver(&["first", "second"]), FakeTransport);
        let result = client.discover_bootstrap().await;

        assert!(
            matches!(result, Err(ClientError::UnexpectedRecordCount(2))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn invalid_record_returns_bootstrap_error() {
        let client = Client::new(RecordsResolver(&["invalid"]), FakeTransport);
        let result = client.discover_bootstrap().await;

        assert!(
            matches!(result, Err(ClientError::Bootstrap(_))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn resolver_failure_returns_resolver_error() {
        let client = Client::new(FailingResolver, FakeTransport);
        let result = client.discover_bootstrap().await;

        assert!(
            matches!(result, Err(ClientError::Resolver(_))),
            "result: {result:?}"
        );
    }

    fn vendor_id() -> VendorId {
        "000000".parse().unwrap()
    }

    fn product() -> Product {
        "dslite-b4".parse().unwrap()
    }

    fn version() -> FirmwareVersion {
        "0_1_0".parse().unwrap()
    }

    fn valid_request() -> ProvisioningRequest {
        ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::DsLite],
            None,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn client_provision_good_path() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            SuccessfulTransport,
        );
        let request = valid_request();

        let response = client
            .provision(&request)
            .await
            .expect("provisioning should succeed")
            .expect("the bootstrap record should exist");

        assert_eq!(response.provider_info().enabler_name(), "example");
        assert_eq!(response.order(), [Capability::DsLite]);
        assert_eq!(
            response.offer(Capability::DsLite),
            Some(&serde_json::json!({"aftr": "dslite.example"}))
        );
    }

    #[tokio::test]
    async fn provision_returns_none_without_a_discovery_record() {
        let client = Client::new(NotFoundResolver, UnexpectedCallTransport);
        let request = valid_request();

        let result = client.provision(&request).await;

        assert!(matches!(result, Ok(None)), "result: {result:?}");
    }

    #[tokio::test]
    async fn provision_rejects_non_utf8_response_body() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            StaticResponseTransport {
                status: 200,
                body: &[0xff],
            },
        );
        let request = valid_request();

        let result = client.provision(&request).await;

        assert!(
            matches!(result, Err(ClientError::ResponseEncoding(_))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_malformed_json_response() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            StaticResponseTransport {
                status: 200,
                body: b"not json",
            },
        );
        let request = valid_request();

        let result = client.provision(&request).await;

        assert!(
            matches!(result, Err(ClientError::ProvisioningResponse(_))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_unexpected_response_status() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            StaticResponseTransport {
                status: 500,
                body: &[],
            },
        );
        let request = valid_request();

        let result = client.provision(&request).await;

        assert!(
            matches!(result, Err(ClientError::UnexpectedResponseStatus(500))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn client_provision_follows_redirect() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectTransport::new(
                "https://redirect.example/provision",
                "redirect.example",
                "/provision",
            ),
        );
        let request = valid_request();

        let response = client
            .provision(&request)
            .await
            .expect("provisioning should succeed")
            .expect("the bootstrap record should exist");

        assert_eq!(response.provider_info().enabler_name(), "example");
        assert_eq!(response.order(), [Capability::DsLite]);
        assert_eq!(
            response.offer(Capability::DsLite),
            Some(&serde_json::json!({"aftr": "dslite.example"}))
        );
    }

    #[tokio::test]
    async fn client_provision_resolves_relative_redirect_location() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/api/provision t=b"]),
            RedirectTransport::new("../next", "example.com", "/next"),
        );

        let result = client.provision(&valid_request()).await;

        assert!(matches!(result, Ok(Some(_))), "result: {result:?}");
    }

    #[tokio::test]
    async fn provision_rejects_redirect_without_location() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectResponseTransport { location: None },
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::MissingLocation))
            ),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_invalid_redirect_location() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectResponseTransport {
                location: Some("https://[invalid"),
            },
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::InvalidLocation(_)))
            ),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_redirect_with_unsupported_scheme() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectResponseTransport {
                location: Some("ftp://redirect.example/provision"),
            },
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::UnsupportedScheme(
                    ref scheme
                ))) if scheme == "ftp"
            ),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_http_redirect_when_certificate_validation_is_required() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectResponseTransport {
                location: Some("http://redirect.example/provision"),
            },
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::RequiresHttps))
            ),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_redirects_above_the_limit() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectResponseTransport {
                location: Some("/provision"),
            },
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::TooManyRedirects))
            ),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_first_redirect_when_max_redirects_is_zero() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectTransport::new(
                "https://redirect.example/provision",
                "redirect.example",
                "/provision",
            ),
        )
        .with_max_redirects(0);
        let request = valid_request();

        let result = client.provision(&request).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::TooManyRedirects))
            ),
            "result: {result:?}"
        );
    }
}
