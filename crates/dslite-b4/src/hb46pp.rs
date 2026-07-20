use hb46pp::{
    Capability, FirmwareVersionError, ProductError, ProvisioningData, ProvisioningRequest,
    ProvisioningRequestError, VendorIdError,
};
use thiserror::Error;

use crate::config::{AftrAddress, DiscoveryConfig};

#[derive(Debug, Error)]
pub enum RequestError {
    #[error(transparent)]
    VendorId(#[from] VendorIdError),
    #[error(transparent)]
    Product(#[from] ProductError),
    #[error(transparent)]
    FirmwareVersion(#[from] FirmwareVersionError),
    #[error(transparent)]
    Request(#[from] ProvisioningRequestError),
}

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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DsliteOfferError {
    #[error("DS-Lite provisioning offer is missing the aftr field")]
    MissingAftr,
    #[error("DS-Lite provisioning offer field aftr must be a string")]
    InvalidAftr,
}

pub fn dslite_aftr(data: &ProvisioningData) -> Result<Option<AftrAddress>, DsliteOfferError> {
    let Some(offer) = data.select(&[Capability::DsLite]) else {
        return Ok(None);
    };

    let Some(aftr) = offer.parameters().get("aftr") else {
        return Err(DsliteOfferError::MissingAftr);
    };
    let Some(aftr) = aftr.as_str() else {
        return Err(DsliteOfferError::InvalidAftr);
    };

    Ok(Some(aftr.to_string().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_dslite_provisioning_request_from_discovery_config() {
        let request = provisioning_request(&DiscoveryConfig::default()).unwrap();

        assert_eq!(request.vendor_id().as_str(), "000000");
        assert_eq!(request.product().as_str(), "dslite-b4");
        assert_eq!(request.version().as_str(), "0_1_0");
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

        let result = dslite_aftr(&data).unwrap();

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

        let result = dslite_aftr(&data).unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn rejects_dslite_offer_without_aftr() {
        let data = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": {}
            }"#,
        )
        .unwrap();

        let result = dslite_aftr(&data);

        assert!(matches!(result, Err(DsliteOfferError::MissingAftr)));
    }

    #[test]
    fn rejects_non_string_aftr() {
        let data = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": {"aftr": 42}
            }"#,
        )
        .unwrap();

        let result = dslite_aftr(&data);

        assert!(matches!(result, Err(DsliteOfferError::InvalidAftr)));
    }
}
