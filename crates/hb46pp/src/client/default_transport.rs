use std::net::SocketAddr;

use reqwest::header;

use crate::TlsPolicy;

use super::{Transport, TransportRequest, TransportResponse};

const MAX_ACCEPTED_RESPONSE_BODY_SIZE: usize = 1024 * 1024;

/// Errors returned by [`DefaultTransport`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DefaultTransportError {
    /// Reqwest could not complete the HTTP request or read its response body.
    #[error("HTTP request failed")]
    Request(#[from] reqwest::Error),

    /// A response header required as text contained an invalid value.
    #[error("response {header} header is not valid text")]
    InvalidHeader {
        /// The name of the invalid response header.
        header: String,
        #[source]
        source: reqwest::header::ToStrError,
    },

    /// The response body exceeded the maximum size accepted by the transport.
    #[error("response body exceeds the maximum accepted size of {limit} bytes")]
    ResponseBodyTooLarge {
        /// The maximum accepted response-body size in bytes.
        limit: usize,
    },

    /// The provisioning endpoint specified a literal IPv4 address.
    #[error("provisioning endpoint cannot use an IPv4 address")]
    Ipv4EndpointNotAllowed,
}

/// Default HTTP transport for HB46PP provisioning requests.
pub struct DefaultTransport {
    validated_client: reqwest::Client,
    unvalidated_client: reqwest::Client,
}

impl DefaultTransport {
    /// Creates a transport with clients for both HB46PP TLS policies.
    pub fn new() -> Result<Self, reqwest::Error> {
        Ok(Self {
            validated_client: build_http_client(false)?,
            unvalidated_client: build_http_client(true)?,
        })
    }
}

impl Transport for DefaultTransport {
    type Error = DefaultTransportError;

    async fn send_once(&self, request: TransportRequest) -> Result<TransportResponse, Self::Error> {
        if matches!(request.endpoint().host(), Some(url::Host::Ipv4(_))) {
            return Err(DefaultTransportError::Ipv4EndpointNotAllowed);
        }

        let client = match request.tls_policy() {
            TlsPolicy::ValidateCertificate => &self.validated_client,
            TlsPolicy::NoCertificateValidation => &self.unvalidated_client,
        };

        let mut response = client.get(request.endpoint().clone()).send().await?;

        let status = response.status().as_u16();
        let location = extract_single_header_value(response.headers(), &header::LOCATION)?;
        let cache_control =
            extract_comma_list_header_value(response.headers(), &header::CACHE_CONTROL)?;

        if response
            .content_length()
            .is_some_and(|length| length > MAX_ACCEPTED_RESPONSE_BODY_SIZE as u64)
        {
            return Err(DefaultTransportError::ResponseBodyTooLarge {
                limit: MAX_ACCEPTED_RESPONSE_BODY_SIZE,
            });
        }

        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            append_response_body_chunk(&mut body, &chunk)?;
        }

        Ok(TransportResponse::new(
            status,
            location,
            cache_control,
            body,
        ))
    }
}

fn extract_single_header_value(
    header_map: &header::HeaderMap,
    header_name: &header::HeaderName,
) -> Result<Option<String>, DefaultTransportError> {
    let value = header_map
        .get(header_name)
        .map(|value| value.to_str().map(str::to_owned))
        .transpose()
        .map_err(|source| DefaultTransportError::InvalidHeader {
            header: header_name.to_string(),
            source,
        })?;

    Ok(value)
}

fn extract_comma_list_header_value(
    header_map: &header::HeaderMap,
    header_name: &header::HeaderName,
) -> Result<Option<String>, DefaultTransportError> {
    let values = header_map
        .get_all(header_name)
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| DefaultTransportError::InvalidHeader {
            header: header_name.to_string(),
            source,
        })?;

    if values.is_empty() {
        Ok(None)
    } else {
        Ok(Some(values.join(", ")))
    }
}

fn append_response_body_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
) -> Result<(), DefaultTransportError> {
    if body.len().saturating_add(chunk.len()) > MAX_ACCEPTED_RESPONSE_BODY_SIZE {
        return Err(DefaultTransportError::ResponseBodyTooLarge {
            limit: MAX_ACCEPTED_RESPONSE_BODY_SIZE,
        });
    }

    body.extend_from_slice(chunk);
    Ok(())
}

struct Ipv6Resolver;

impl reqwest::dns::Resolve for Ipv6Resolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let addresses = ipv6_addresses(addresses);

            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn ipv6_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    addresses.into_iter().filter(SocketAddr::is_ipv6).collect()
}

fn build_http_client(accept_invalid_certificates: bool) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        // Redirect validation and policy are handled by the HB46PP client.
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .tls_danger_accept_invalid_certs(accept_invalid_certificates)
        .dns_resolver(Ipv6Resolver)
        .build()
}

#[cfg(test)]
mod tests {
    use super::super::cache_control_contains_no_store;
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    async fn spawn_http_server(response: &'static [u8]) -> (url::Url, JoinHandle<()>) {
        let listener = TcpListener::bind("[::1]:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 1024];
                let bytes_read = stream.read(&mut buffer).await.unwrap();

                if bytes_read == 0 {
                    break;
                }

                request.extend_from_slice(&buffer[..bytes_read]);

                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            assert!(request.starts_with(b"GET /provision HTTP/1.1\r\n"));

            stream.write_all(response).await.unwrap();
        });

        let endpoint = url::Url::parse(&format!("http://{address}/provision")).unwrap();

        (endpoint, server)
    }

    #[test]
    fn ipv6_addresses_removes_ipv4_addresses() {
        let ipv4 = "192.0.2.1:443".parse().unwrap();
        let ipv6 = "[2001:db8::1]:443".parse().unwrap();

        let result = ipv6_addresses([ipv4, ipv6]);

        assert_eq!(result, [ipv6]);
    }

    #[test]
    fn extract_header_value_returns_none_when_missing() {
        let headers = header::HeaderMap::new();

        let result = extract_single_header_value(&headers, &header::LOCATION);

        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn extract_header_value_identifies_an_invalid_header() {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::LOCATION,
            header::HeaderValue::from_bytes(b"\xff").unwrap(),
        );

        let result = extract_single_header_value(&headers, &header::LOCATION);

        assert!(
            matches!(
                &result,
                Err(DefaultTransportError::InvalidHeader { header, .. })
                    if header == "location"
            ),
            "result: {result:?}"
        );
    }

    #[test]
    fn response_body_accepts_the_maximum_size() {
        let mut body = Vec::new();
        let chunk = vec![0; MAX_ACCEPTED_RESPONSE_BODY_SIZE];

        let result = append_response_body_chunk(&mut body, &chunk);

        assert!(result.is_ok(), "result: {result:?}");
        assert_eq!(body.len(), MAX_ACCEPTED_RESPONSE_BODY_SIZE);
    }

    #[test]
    fn response_body_rejects_data_above_the_maximum_size() {
        let mut body = vec![0; MAX_ACCEPTED_RESPONSE_BODY_SIZE];
        let result = append_response_body_chunk(&mut body, &[0]);

        assert!(
            matches!(
                result,
                Err(DefaultTransportError::ResponseBodyTooLarge { limit })
                    if limit == MAX_ACCEPTED_RESPONSE_BODY_SIZE
            ),
            "result: {result:?}"
        );

        // Rejected data must not be appended.
        assert_eq!(body.len(), MAX_ACCEPTED_RESPONSE_BODY_SIZE);
    }

    #[tokio::test]
    async fn default_transport_rejects_an_ipv4_literal_endpoint() {
        let transport = DefaultTransport::new().unwrap();
        let request = TransportRequest::new(
            url::Url::parse("https://192.0.2.1/provision").unwrap(),
            TlsPolicy::ValidateCertificate,
        );

        let result = transport.send_once(request).await;

        assert!(matches!(
            result,
            Err(DefaultTransportError::Ipv4EndpointNotAllowed)
        ));
    }

    #[test]
    fn extract_header_values_combines_repeated_headers() {
        let mut headers = header::HeaderMap::new();
        headers.append(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("max-age=3600"),
        );
        headers.append(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );

        let result = extract_comma_list_header_value(&headers, &header::CACHE_CONTROL)
            .unwrap()
            .unwrap();

        assert!(cache_control_contains_no_store(&result));
    }

    #[tokio::test]
    async fn default_transport_reads_an_http_response_over_ipv6() {
        let raw_response = b"HTTP/1.1 200 OK\r\n\
  Content-Length: 12\r\n\
  Location: /next\r\n\
  Cache-Control: max-age=3600\r\n\
  Cache-Control: no-store\r\n\
  Connection: close\r\n\
  \r\n\
  {\"order\":[]}";

        let (endpoint, server) = spawn_http_server(raw_response).await;
        let transport = DefaultTransport::new().unwrap();
        let request = TransportRequest::new(endpoint, TlsPolicy::NoCertificateValidation);

        let result = transport.send_once(request).await;
        server.await.unwrap();

        let response = result.unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(response.location(), Some("/next"));
        assert_eq!(response.cache_control(), Some("max-age=3600, no-store"));
        assert_eq!(response.body(), br#"{"order":[]}"#);
    }

    #[tokio::test]
    async fn default_transport_does_not_follow_redirects() {
        let raw_response = b"HTTP/1.1 307 Temporary Redirect\r\n\
  Location: /next\r\n\
  Content-Length: 0\r\n\
  Connection: close\r\n\
  \r\n";

        let (endpoint, server) = spawn_http_server(raw_response).await;
        let transport = DefaultTransport::new().unwrap();
        let request = TransportRequest::new(endpoint, TlsPolicy::NoCertificateValidation);

        let result = transport.send_once(request).await;
        server.await.unwrap();

        let response = result.unwrap();

        assert_eq!(response.status(), 307);
        assert_eq!(response.location(), Some("/next"));
    }
}
