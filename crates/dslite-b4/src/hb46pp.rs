//! Conversion between daemon discovery configuration and HB46PP models.

use hb46pp::{
    Capability, FirmwareVersionError, ProductError, ProvisioningData, ProvisioningRequest,
    ProvisioningRequestError, TunnelEndpoint, VendorIdError,
};
use thiserror::Error;

use crate::config::{AftrAddress, DiscoveryConfig};

#[derive(Debug, Error)]
/// Errors constructing an HB46PP provisioning request.
pub enum RequestError {
    #[error(transparent)]
    /// The configured vendor identifier is invalid.
    VendorId(#[from] VendorIdError),
    #[error(transparent)]
    /// The configured product identifier is invalid.
    Product(#[from] ProductError),
    #[error(transparent)]
    /// The daemon version cannot be represented on the wire.
    FirmwareVersion(#[from] FirmwareVersionError),
    #[error(transparent)]
    /// The complete request violates an HB46PP constraint.
    Request(#[from] ProvisioningRequestError),
}

/// Constructs a DS Lite provisioning request from daemon configuration.
pub fn provisioning_request(config: &DiscoveryConfig) -> Result<ProvisioningRequest, RequestError> {
    let vendor_id = config.vendor_id.parse()?;
    let product = config.product.parse()?;
    let version = env!("CARGO_PKG_VERSION").replace('.', "_").parse()?;

    ProvisioningRequest::new(
        vendor_id,
        product,
        version,
        vec![Capability::DsLite],
        None,
        None,
    )
    .map_err(RequestError::from)
}

/// Extracts the AFTR endpoint from the selected DS Lite offer, if present.
pub fn dslite_aftr(data: &ProvisioningData) -> Option<AftrAddress> {
    data.select(&[Capability::DsLite])?;
    let parameters = data.dslite()?;
    Some(match parameters.aftr() {
        TunnelEndpoint::Ipv6(address) => AftrAddress::Ip(*address),
        TunnelEndpoint::DnsName(name) => AftrAddress::Fqdn(name.as_str().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_dslite_provisioning_request_from_discovery_config() {
        let request = provisioning_request(&DiscoveryConfig::default()).unwrap();

        assert_eq!(request.vendor_id().as_str(), "000000");
        assert_eq!(request.product().as_str(), "dslite-b4");
        assert_eq!(
            request.version().as_str(),
            env!("CARGO_PKG_VERSION").replace('.', "_")
        );
        assert_eq!(request.capabilities(), &[Capability::DsLite]);
        assert!(request.token().is_none());
        assert!(request.credentials().is_none());
    }

    #[test]
    fn converts_dslite_offer_to_aftr_address() {
        let data = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": {"aftr": "aftr.example"}
            }"#,
        )
        .unwrap();

        let result = dslite_aftr(&data);

        assert!(matches!(
            result,
            Some(AftrAddress::Fqdn(ref name)) if name == "aftr.example"
        ));
    }

    #[test]
    fn returns_none_when_dslite_is_not_offered() {
        let data = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": [],
                "dslite": {"aftr": "aftr.example"}
            }"#,
        )
        .unwrap();

        let result = dslite_aftr(&data);

        assert!(result.is_none());
    }

    #[test]
    fn malformed_dslite_offer_is_rejected_while_parsing() {
        let result = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": {}
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn non_string_aftr_is_rejected_while_parsing() {
        let result = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": {"aftr": 42}
            }"#,
        );

        assert!(result.is_err());
    }
}
