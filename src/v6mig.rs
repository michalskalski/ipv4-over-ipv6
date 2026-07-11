use thiserror::Error;
use url::Url;

const V6MIG_SPEC: &str = "v6mig-1";

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("url: {0}, err: {1}")]
    InvalidUrl(String, String),
    #[error("extracting tls policy : {0}")]
    InvalidTlsPolicy(String),
    #[error("parsing field, expected: '{0}', got: '{1}'")]
    MalformedField(String, String),
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("unsupported spec version: {0}")]
    UnsupportedVersion(String),
    #[error("tls policy set to validate for http scheme")]
    InvalidTlsForHttp,
    #[error("record contain data beyond spec fields, record: {0}")]
    InvalidRecord(String),
}

#[derive(Debug)]
struct Bootstrap {
    url: Url,
    validate_tls: bool,
}

impl Bootstrap {
    pub fn parse(txt: &str) -> Result<Self, BootstrapError> {
        let mut iter = txt.split(' ');

        let version_field = iter.next().ok_or(BootstrapError::MissingField("v"))?;
        let version_value = parse_field(version_field, "v")?;
        if version_value != V6MIG_SPEC {
            return Err(BootstrapError::UnsupportedVersion(
                version_value.to_string(),
            ));
        }

        let url_field = iter.next().ok_or(BootstrapError::MissingField("url"))?;
        let url_value = parse_field(url_field, "url")?;

        let tls_field = iter.next().ok_or(BootstrapError::MissingField("t"))?;
        let tls_value = parse_field(tls_field, "t")?;

        if iter.next().is_some() {
            return Err(BootstrapError::InvalidRecord(txt.to_string()));
        };

        let validate_tls = match tls_value {
            "a" => false,
            "b" => true,
            _ => {
                return Err(BootstrapError::InvalidTlsPolicy(format!(
                    "invalid tls policy value: {tls_value}, expected '<a|b>'"
                )));
            }
        };

        let url = Url::parse(url_value)
            .map_err(|e| BootstrapError::InvalidUrl(url_value.to_string(), e.to_string()))?;

        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(BootstrapError::InvalidUrl(
                url_value.to_string(),
                format!(
                    "unsuported url scheme: {}, supported: <http|https>",
                    url.scheme(),
                ),
            ));
        };

        if url.scheme() == "http" && validate_tls {
            return Err(BootstrapError::InvalidTlsForHttp);
        };

        Ok(Bootstrap { url, validate_tls })
    }
}

fn parse_field<'a>(field: &'a str, expected_key: &'static str) -> Result<&'a str, BootstrapError> {
    let (key, value) = field.split_once('=').ok_or(BootstrapError::MalformedField(
        format!("{expected_key}=<value>"),
        field.to_string(),
    ))?;

    if key != expected_key {
        return Err(BootstrapError::MalformedField(
            expected_key.to_string(),
            key.to_string(),
        ));
    };
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V6CONNECT_BOOTSTRAP: &str =
        "v=v6mig-1 url=https://prod.v6mig.v6connect.net/cpe/v1/config t=b";

    #[test]
    fn parses_v6connect_bootstrap_record() {
        let bootstrap = Bootstrap::parse(V6CONNECT_BOOTSTRAP).unwrap();

        assert_eq!(
            bootstrap.url.as_str(),
            "https://prod.v6mig.v6connect.net/cpe/v1/config"
        );
        assert!(bootstrap.validate_tls);
    }

    #[test]
    fn accepts_http_without_tls_validation() {
        let bootstrap = Bootstrap::parse("v=v6mig-1 url=http://vne.example/rule.cgi t=a").unwrap();

        assert_eq!(bootstrap.url.scheme(), "http");
        assert!(!bootstrap.validate_tls);
    }

    #[test]
    fn rejects_missing_url_field() {
        let error = Bootstrap::parse("v=v6mig-1").unwrap_err();

        assert!(matches!(error, BootstrapError::MissingField(_)));
    }

    #[test]
    fn rejects_fields_out_of_order() {
        let error = Bootstrap::parse("url=https://vne.example/rule.cgi v=v6mig-1 t=b").unwrap_err();

        assert!(matches!(error, BootstrapError::MalformedField(_, _)));
    }

    #[test]
    fn rejects_unsupported_version() {
        let error = Bootstrap::parse("v=v6mig-2 url=https://vne.example/rule.cgi t=b").unwrap_err();

        assert!(matches!(error, BootstrapError::UnsupportedVersion(_)));
    }

    #[test]
    fn rejects_non_http_url_scheme() {
        let error = Bootstrap::parse("v=v6mig-1 url=ftp://vne.example/rule.cgi t=a").unwrap_err();

        assert!(matches!(error, BootstrapError::InvalidUrl(_, _)));
    }

    #[test]
    fn rejects_http_with_tls_validation() {
        let error = Bootstrap::parse("v=v6mig-1 url=http://vne.example/rule.cgi t=b").unwrap_err();

        assert!(matches!(error, BootstrapError::InvalidTlsForHttp));
    }

    #[test]
    fn rejects_extra_fields() {
        let error = Bootstrap::parse("v=v6mig-1 url=https://vne.example/rule.cgi t=b extra=value")
            .unwrap_err();

        assert!(matches!(error, BootstrapError::InvalidRecord(_)));
    }
}
