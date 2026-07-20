use std::string::FromUtf8Error;

use hickory_resolver::{
    net::NetError,
    proto::rr::{RData, rdata::TXT},
};

use super::{DiscoveryAnswer, DiscoveryResolver};

/// Errors returned by [`DefaultDiscoveryResolver`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DefaultDiscoveryError {
    /// The DNS resolver could not complete the TXT lookup.
    #[error("TXT lookup failed")]
    Lookup(#[source] NetError),

    /// A returned TXT resource record was not valid UTF-8.
    #[error("TXT record is not a valid UTF-8")]
    InvalidEncoding(#[source] FromUtf8Error),
}

/// An HB46PP discovery resolver backed by Hickory and Tokio.
///
/// The resolver reads the system DNS configuration but performs queries
/// independently of libc and NSS.
pub struct DefaultDiscoveryResolver {
    inner: hickory_resolver::TokioResolver,
}

impl DefaultDiscoveryResolver {
    /// Creates a resolver using the system DNS configuration.
    pub fn new() -> Result<Self, DefaultDiscoveryError> {
        let builder =
            hickory_resolver::Resolver::builder_tokio().map_err(DefaultDiscoveryError::Lookup)?;

        let inner = builder.build().map_err(DefaultDiscoveryError::Lookup)?;

        Ok(Self { inner })
    }
}

impl DiscoveryResolver for DefaultDiscoveryResolver {
    type Error = DefaultDiscoveryError;

    async fn lookup_txt(&self, name: &str) -> Result<DiscoveryAnswer, Self::Error> {
        let lookup = match self.inner.txt_lookup(name).await {
            Ok(lookup) => lookup,
            Err(error) if error.is_no_records_found() => {
                return Ok(DiscoveryAnswer::NotFound);
            }
            Err(error) => return Err(DefaultDiscoveryError::Lookup(error)),
        };

        let mut records = Vec::new();
        for answer in lookup.answers() {
            let RData::TXT(txt) = &answer.data else {
                continue;
            };

            let record = decode_txt_record(txt).map_err(DefaultDiscoveryError::InvalidEncoding)?;

            records.push(record);
        }
        Ok(DiscoveryAnswer::Records(records))
    }
}

fn decode_txt_record(txt: &TXT) -> Result<String, FromUtf8Error> {
    String::from_utf8(txt.txt_data.concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_txt_record_joins_fragments() {
        let txt = TXT::from_bytes(vec![
            b"v=v6mig-1 url=https://",
            b"example.com/provision t=b",
        ]);

        let result = decode_txt_record(&txt);

        assert_eq!(
            result.as_deref(),
            Ok("v=v6mig-1 url=https://example.com/provision t=b")
        );
    }

    #[test]
    fn decode_txt_record_rejects_invalid_utf8() {
        let txt = TXT::from_bytes(vec![&[0xff]]);

        let result = decode_txt_record(&txt);

        assert!(result.is_err());
    }
}
