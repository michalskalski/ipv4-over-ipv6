use url::Url;

use crate::{
    Bootstrap, BootstrapError, ProvisioningData, ProvisioningDataError, ProvisioningRequest,
    ProvisioningUrlError, TlsPolicy,
};
use std::{error::Error, future::Future, str::Utf8Error, time::Duration};

#[cfg(feature = "default-resolver")]
mod default_resolver;
#[cfg(feature = "default-resolver")]
pub use default_resolver::{DefaultDiscoveryError, DefaultDiscoveryResolver};

#[cfg(feature = "default-transport")]
mod default_transport;
#[cfg(feature = "default-transport")]
pub use default_transport::{DefaultTransport, DefaultTransportError};

const DISCOVERY_NAME: &str = "4over6.info.";
const DEFAULT_MAX_REDIRECTS: usize = 10;
const DISCOVERY_NOT_FOUND_MIN: Duration = Duration::from_secs(60 * 60);
const DISCOVERY_NOT_FOUND_MAX: Duration = Duration::from_secs(3 * 60 * 60);
const DISCOVERY_FAILURE_MIN: Duration = Duration::from_secs(60);
const DISCOVERY_FAILURE_MAX: Duration = Duration::from_secs(10 * 60);
const PROVISIONING_FAILURE_MIN: Duration = Duration::from_secs(10 * 60);
const PROVISIONING_FAILURE_MAX: Duration = Duration::from_secs(30 * 60);
const DEFAULT_REFRESH_MIN: Duration = Duration::from_secs(20 * 60 * 60);
const DEFAULT_REFRESH_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// The interval in which HB46PP recommends making another provisioning attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextAttemptWindow {
    min: Duration,
    max: Duration,
}

impl NextAttemptWindow {
    fn new(min: Duration, max: Duration) -> Self {
        Self { min, max }
    }

    fn exact(delay: Duration) -> Self {
        Self::new(delay, delay)
    }

    /// Returns the earliest recommended delay before the next attempt.
    pub fn min(&self) -> Duration {
        self.min
    }

    /// Returns the latest recommended delay before the next attempt.
    pub fn max(&self) -> Duration {
        self.max
    }
}

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

    /// Returns the certificate validation policy from the bootstrap record.
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

/// A successful HB46PP provisioning response and its HTTP cache metadata.
#[derive(Debug)]
pub struct ProvisioningResponse {
    data: ProvisioningData,
    cache_control: Option<String>,
}

impl ProvisioningResponse {
    /// Returns the parsed HB46PP provisioning data.
    pub fn data(&self) -> &ProvisioningData {
        &self.data
    }

    /// Returns the `Cache-Control` header value from the successful response.
    pub fn cache_control(&self) -> Option<&str> {
        self.cache_control.as_deref()
    }

    /// Returns whether `Cache-Control` permits persistent storage.
    ///
    /// This returns `false` when the response contains the `no-store`
    /// directive. It does not determine freshness or whether a stored response
    /// can be reused without revalidation.
    pub fn may_persist(&self) -> bool {
        !self
            .cache_control
            .as_deref()
            .is_some_and(cache_control_contains_no_store)
    }

    /// Returns when the response should be refreshed.
    ///
    /// A response TTL produces an exact delay. When the response omits its
    /// TTL, HB46PP specifies a randomized delay between 20 and 24 hours.
    pub fn next_attempt_window(&self) -> NextAttemptWindow {
        match self.data.ttl() {
            Some(ttl) => NextAttemptWindow::exact(Duration::from_secs(u64::from(ttl.as_secs()))),
            None => NextAttemptWindow::new(DEFAULT_REFRESH_MIN, DEFAULT_REFRESH_MAX),
        }
    }
}

/// The outcome of a completed HB46PP provisioning attempt.
#[derive(Debug)]
pub enum ProvisioningOutcome {
    /// A bootstrap record was found and provisioning data was received.
    Provisioned(ProvisioningResponse),
    /// DNS returned NXDOMAIN or NODATA for the bootstrap discovery name.
    NotFound,
}

impl ProvisioningOutcome {
    /// Returns the interval in which HB46PP recommends another attempt.
    pub fn next_attempt_window(&self) -> NextAttemptWindow {
        match self {
            Self::Provisioned(response) => response.next_attempt_window(),
            Self::NotFound => {
                NextAttemptWindow::new(DISCOVERY_NOT_FOUND_MIN, DISCOVERY_NOT_FOUND_MAX)
            }
        }
    }
}

fn cache_control_contains_no_store(value: &str) -> bool {
    for directive in value.split(',') {
        let name = match directive.split_once('=') {
            Some((name, _value)) => name,
            None => directive,
        };

        if name.trim().eq_ignore_ascii_case("no-store") {
            return true;
        }
    }

    false
}

/// The result of looking up the HB46PP bootstrap discovery record.
#[derive(Debug, PartialEq, Eq)]
pub enum DiscoveryAnswer {
    /// Complete TXT resource records.
    ///
    /// Each string represents one resource record after its DNS fragments have
    /// been joined in wire order.
    Records(Vec<String>),
    /// No bootstrap record exists because the lookup returned NXDOMAIN or NODATA.
    NotFound,
}

/// Resolves TXT records used for HB46PP bootstrap discovery.
///
/// This trait is limited to the protocol's discovery record. Resolving the
/// provisioning endpoint hostname remains the transport's responsibility.
pub trait DiscoveryResolver: Send + Sync {
    /// The error returned by the resolver when a TXT lookup fails.
    type Error: Error + Send + Sync + 'static;

    /// Looks up the TXT records for an HB46PP discovery name.
    ///
    /// Implementations must return [`DiscoveryAnswer::NotFound`] for NXDOMAIN
    /// and NODATA. Other resolver failures must be returned as `Err`.
    /// Fragments belonging to one TXT resource record must be joined before
    /// returning [`DiscoveryAnswer::Records`].
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
    /// The error returned by the transport when sending a request fails.
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
    /// The redirect target specified a literal IPv4 address.
    #[error("redirect target cannot use an IPv4 address")]
    Ipv4TargetNotAllowed,
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
    #[error("unable to parse provisioning data")]
    ProvisioningData(#[source] ProvisioningDataError),
    /// The server returned an invalid or disallowed redirect.
    #[error("failed to follow redirect")]
    Redirect(#[source] RedirectError),
    /// The server returned an HTTP status not handled as an HB46PP response.
    #[error("server returned unexpected http response code: {0}")]
    UnexpectedResponseStatus(u16),
}

impl ClientError {
    /// Returns the interval in which HB46PP recommends retrying this failure.
    ///
    /// `None` means HB46PP does not prescribe a retry window for the failure.
    pub fn next_attempt_window(&self) -> Option<NextAttemptWindow> {
        match self {
            Self::Resolver(_) => Some(NextAttemptWindow::new(
                DISCOVERY_FAILURE_MIN,
                DISCOVERY_FAILURE_MAX,
            )),
            Self::UnexpectedRecordCount(_) | Self::Bootstrap(_) => Some(NextAttemptWindow::new(
                DISCOVERY_NOT_FOUND_MIN,
                DISCOVERY_NOT_FOUND_MAX,
            )),
            Self::Transport(_)
            | Self::ResponseEncoding(_)
            | Self::ProvisioningData(_)
            | Self::UnexpectedResponseStatus(_) => Some(NextAttemptWindow::new(
                PROVISIONING_FAILURE_MIN,
                PROVISIONING_FAILURE_MAX,
            )),
            Self::ProvisioningUrl(_) | Self::Redirect(_) => None,
        }
    }
}

/// An HB46PP provisioning client using network adapters provided by the caller.
pub struct Client<R, T> {
    resolver: R,
    transport: T,
    max_redirects: usize,
}

/// An HB46PP client using the default DNS resolver and HTTP transport.
#[cfg(feature = "default-client")]
pub type DefaultClient = Client<DefaultDiscoveryResolver, DefaultTransport>;

/// Errors returned while constructing a [`DefaultClient`].
#[cfg(feature = "default-client")]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DefaultClientError {
    /// The system DNS configuration could not initialize the resolver.
    #[error("failed to create the default discovery resolver")]
    Resolver(#[from] DefaultDiscoveryError),

    /// Reqwest could not initialize the HTTP transport.
    #[error("failed to create the default HTTP transport")]
    Transport(#[from] reqwest::Error),
}

#[cfg(feature = "default-client")]
impl Client<DefaultDiscoveryResolver, DefaultTransport> {
    /// Creates a client using the default DNS resolver and HTTP transport.
    pub fn try_new() -> Result<Self, DefaultClientError> {
        let resolver = DefaultDiscoveryResolver::new()?;
        let transport = DefaultTransport::new()?;

        Ok(Self::new(resolver, transport))
    }
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
    /// Returns [`ProvisioningOutcome::NotFound`] when the discovery name has
    /// no TXT record. A valid provisioning response is parsed and returned as
    /// [`ProvisioningOutcome::Provisioned`].
    pub async fn provision(
        &self,
        request: &ProvisioningRequest,
    ) -> Result<ProvisioningOutcome, ClientError> {
        let Some(bootstrap) = self.discover_bootstrap().await? else {
            return Ok(ProvisioningOutcome::NotFound);
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
                    let provisioning_data =
                        ProvisioningData::parse(body).map_err(ClientError::ProvisioningData)?;

                    return Ok(ProvisioningOutcome::Provisioned(ProvisioningResponse {
                        data: provisioning_data,
                        cache_control: response.cache_control,
                    }));
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

    if matches!(endpoint.host(), Some(url::Host::Ipv4(_))) {
        return Err(RedirectError::Ipv4TargetNotAllowed);
    }

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use crate::{Capability, Credentials, FirmwareVersion, Product, VendorId};

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
                Some("max-age=3600, NO-STORE".to_string()),
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

    struct DiscoveryNameResolver;

    impl DiscoveryResolver for DiscoveryNameResolver {
        type Error = Infallible;

        fn lookup_txt(
            &self,
            name: &str,
        ) -> impl Future<Output = Result<DiscoveryAnswer, Self::Error>> {
            assert_eq!(name, "4over6.info.");
            future::ready(Ok(DiscoveryAnswer::NotFound))
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

    fn expect_provisioned(outcome: ProvisioningOutcome) -> ProvisioningResponse {
        match outcome {
            ProvisioningOutcome::Provisioned(response) => response,
            ProvisioningOutcome::NotFound => panic!("the bootstrap record should exist"),
        }
    }

    fn response_with_ttl(ttl: Option<u64>) -> ProvisioningResponse {
        let ttl = ttl.map_or_else(String::new, |ttl| format!(r#""ttl": {ttl},"#));
        let data = ProvisioningData::parse(&format!(
            r#"{{
                "enabler_name": "example",
                {ttl}
                "order": []
            }}"#
        ))
        .unwrap();

        ProvisioningResponse {
            data,
            cache_control: None,
        }
    }

    #[test]
    fn response_ttl_produces_exact_next_attempt_window() {
        let response = response_with_ttl(Some(61_200));
        let window = response.next_attempt_window();

        assert_eq!(window.min(), Duration::from_secs(61_200));
        assert_eq!(window.max(), Duration::from_secs(61_200));
    }

    #[test]
    fn response_without_ttl_uses_default_refresh_window() {
        let response = response_with_ttl(None);
        let window = response.next_attempt_window();

        assert_eq!(window.min(), Duration::from_secs(20 * 60 * 60));
        assert_eq!(window.max(), Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn not_found_uses_discovery_retry_window() {
        let window = ProvisioningOutcome::NotFound.next_attempt_window();

        assert_eq!(window.min(), Duration::from_secs(60 * 60));
        assert_eq!(window.max(), Duration::from_secs(3 * 60 * 60));
    }

    #[test]
    fn client_errors_only_expose_specified_retry_windows() {
        let resolver = ClientError::Resolver(Box::new(std::io::Error::other("failed")));
        let malformed_discovery = ClientError::UnexpectedRecordCount(2);
        let provisioning = ClientError::UnexpectedResponseStatus(500);
        let unspecified = ClientError::Redirect(RedirectError::MissingLocation);

        assert_eq!(
            resolver.next_attempt_window(),
            Some(NextAttemptWindow::new(
                Duration::from_secs(60),
                Duration::from_secs(10 * 60)
            ))
        );
        assert_eq!(
            malformed_discovery.next_attempt_window(),
            Some(NextAttemptWindow::new(
                Duration::from_secs(60 * 60),
                Duration::from_secs(3 * 60 * 60)
            ))
        );
        assert_eq!(
            provisioning.next_attempt_window(),
            Some(NextAttemptWindow::new(
                Duration::from_secs(10 * 60),
                Duration::from_secs(30 * 60)
            ))
        );
        assert_eq!(unspecified.next_attempt_window(), None);
    }

    #[tokio::test]
    async fn client_provision_good_path() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            SuccessfulTransport,
        );
        let request = valid_request();

        let outcome = client
            .provision(&request)
            .await
            .expect("provisioning should succeed");
        let response = expect_provisioned(outcome);
        let data = response.data();

        assert_eq!(data.provider_info().enabler_name(), "example");
        assert_eq!(data.order(), [Capability::DsLite]);
        assert_eq!(
            data.offer(Capability::DsLite),
            Some(&serde_json::json!({"aftr": "dslite.example"}))
        );
        assert_eq!(response.cache_control(), Some("max-age=3600, NO-STORE"));
        assert!(!response.may_persist());
    }

    #[tokio::test]
    async fn provision_returns_not_found_without_a_discovery_record() {
        let client = Client::new(NotFoundResolver, UnexpectedCallTransport);
        let request = valid_request();

        let result = client.provision(&request).await;

        assert!(matches!(result, Ok(ProvisioningOutcome::NotFound)));
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
            matches!(result, Err(ClientError::ProvisioningData(_))),
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

        let outcome = client
            .provision(&request)
            .await
            .expect("provisioning should succeed");
        let response = expect_provisioned(outcome);
        let data = response.data();

        assert_eq!(data.provider_info().enabler_name(), "example");
        assert_eq!(data.order(), [Capability::DsLite]);
        assert_eq!(
            data.offer(Capability::DsLite),
            Some(&serde_json::json!({"aftr": "dslite.example"}))
        );
        assert!(response.may_persist());
    }

    #[tokio::test]
    async fn client_provision_resolves_relative_redirect_location() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/api/provision t=b"]),
            RedirectTransport::new("../next", "example.com", "/next"),
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(result, Ok(ProvisioningOutcome::Provisioned(_))),
            "result: {result:?}"
        );
    }

    #[tokio::test]
    async fn provision_rejects_redirect_to_unexpected_credential_host() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectTransport::new(
                "https://redirect.example/provision",
                "redirect.example",
                "/provision",
            ),
        );
        let credentials = Credentials::for_server(
            "user".to_string(),
            "password".to_string(),
            "example.com".to_string(),
        )
        .expect("credentials should be valid");
        let request = ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::DsLite],
            None,
            Some(credentials),
        )
        .expect("request should be valid");

        let result = client.provision(&request).await;

        assert!(
            matches!(
                result,
                Err(ClientError::ProvisioningUrl(
                    ProvisioningUrlError::UnexpectedProvisioningHost
                ))
            ),
            "result: {result:?}"
        );
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

    #[tokio::test]
    async fn discovery_queries_absolute_protocol_name() {
        let client = Client::new(DiscoveryNameResolver, FakeTransport);

        let result = client.discover_bootstrap().await;

        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn provision_rejects_redirect_to_ipv4_literal() {
        let client = Client::new(
            RecordsResolver(&["v=v6mig-1 url=https://example.com/provision t=b"]),
            RedirectResponseTransport {
                location: Some("https://192.0.2.1/provision"),
            },
        );

        let result = client.provision(&valid_request()).await;

        assert!(
            matches!(
                result,
                Err(ClientError::Redirect(RedirectError::Ipv4TargetNotAllowed))
            ),
            "result: {result:?}"
        );
    }
}
