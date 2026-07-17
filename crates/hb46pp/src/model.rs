use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use thiserror::Error;
use url::{Host, Url};

const V6MIG_SPEC: &str = "v6mig-1";
const MAX_TTL_SECS: u64 = 604_800;

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
    #[error("provisioning URL must contain a host")]
    MissingUrlHost,
    #[error("record contain data beyond spec fields, record: {0}")]
    InvalidRecord(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Xlat464,
    DsLite,
    IpIp,
    Lw4o6,
    MapE,
    MapT,
}

impl Capability {
    const ALL: [Self; 6] = [
        Self::Xlat464,
        Self::DsLite,
        Self::IpIp,
        Self::Lw4o6,
        Self::MapE,
        Self::MapT,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xlat464 => "464xlat",
            Self::DsLite => "dslite",
            Self::IpIp => "ipip",
            Self::Lw4o6 => "lw4o6",
            Self::MapE => "map_e",
            Self::MapT => "map_t",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("unsupported HB46PP capability: {0}")]
    UnsupportedName(String),
}

impl FromStr for Capability {
    type Err = CapabilityError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.as_str() == value)
            .ok_or_else(|| CapabilityError::UnsupportedName(value.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TtlError {
    #[error("TTL must be at most {MAX_TTL_SECS} seconds")]
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ttl(u32);

impl Ttl {
    pub fn as_secs(self) -> u32 {
        self.0
    }
}

impl TryFrom<u64> for Ttl {
    type Error = TtlError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value > MAX_TTL_SECS {
            return Err(TtlError::TooLarge);
        }

        Ok(Self(value as u32))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Required,
    Rejected,
    Accepted,
}

impl AuthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "req",
            Self::Rejected => "bad",
            Self::Accepted => "ok",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthStatusError {
    #[error("unsupported HB46PP auth status: {0}")]
    UnsupportedStatus(String),
}

impl FromStr for AuthStatus {
    type Err = AuthStatusError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "req" => Ok(Self::Required),
            "bad" => Ok(Self::Rejected),
            "ok" => Ok(Self::Accepted),
            _ => Err(AuthStatusError::UnsupportedStatus(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInfo {
    enabler_name: String,
    service_name: Option<String>,
    isp_name: Option<String>,
}

impl ProviderInfo {
    pub fn enabler_name(&self) -> &str {
        &self.enabler_name
    }

    pub fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    pub fn isp_name(&self) -> Option<&str> {
        self.isp_name.as_deref()
    }
}

pub struct SelectedOffer<'a> {
    capability: Capability,
    parameters: &'a serde_json::Value,
}

impl SelectedOffer<'_> {
    pub fn capability(&self) -> Capability {
        self.capability
    }

    pub fn parameters(&self) -> &serde_json::Value {
        self.parameters
    }
}

#[derive(Debug, Error)]
pub enum ProvisioningResponseError {
    #[error("response is not a JSON object")]
    NotObject,
    #[error("missing required response field: {0}")]
    MissingField(&'static str),
    #[error("response field must not be null: {0}")]
    NullField(&'static str),
    #[error("invalid response field {field}: {source}")]
    InvalidField {
        field: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("response field exceeds 256 bytes including quotes: {0}")]
    InformationalNameTooLong(&'static str),
    #[error(transparent)]
    Ttl(#[from] TtlError),
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error(transparent)]
    AuthStatus(#[from] AuthStatusError),
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    #[error("duplicate capability in response order: {0:?}")]
    DuplicateOrder(Capability),
    #[error("response order lists a method without its provisioning payload: {0:?}")]
    MissingOffer(Capability),
}

#[derive(Debug, Clone)]
pub struct ProvisioningResponse {
    provider_info: ProviderInfo,
    ttl: Option<Ttl>,
    token: Option<Token>,
    auth: Option<AuthStatus>,
    order: Vec<Capability>,
    ipv6_mostly: Option<bool>,
    offers: BTreeMap<Capability, Value>,
}

impl ProvisioningResponse {
    pub fn parse(input: &str) -> Result<Self, ProvisioningResponseError> {
        let value = serde_json::from_str(input).map_err(|source| {
            ProvisioningResponseError::InvalidField {
                field: "response",
                source,
            }
        })?;
        let mut fields = match value {
            Value::Object(fields) => fields,
            _ => return Err(ProvisioningResponseError::NotObject),
        };

        let enabler_name = take_required::<String>(&mut fields, "enabler_name")?;
        validate_informational_name("enabler_name", &enabler_name)?;
        let service_name = take_optional::<String>(&mut fields, "service_name")?;
        if let Some(service_name) = &service_name {
            validate_informational_name("service_name", service_name)?;
        }
        let isp_name = take_optional::<String>(&mut fields, "isp_name")?;
        if let Some(isp_name) = &isp_name {
            validate_informational_name("isp_name", isp_name)?;
        }

        let ttl = take_optional::<u64>(&mut fields, "ttl")
            .map(|ttl| ttl.map(Ttl::try_from).transpose())??;
        let token = take_optional::<String>(&mut fields, "token")
            .map(|token| token.map(|token| token.parse()).transpose())??;
        let auth = take_optional::<String>(&mut fields, "auth")
            .map(|auth| auth.map(|auth| auth.parse()).transpose())??;
        let order_names = take_required::<Vec<String>>(&mut fields, "order")?;
        let ipv6_mostly = take_optional::<bool>(&mut fields, "ipv6_mostly")?;

        let mut order = Vec::with_capacity(order_names.len());
        for name in order_names {
            let capability = name.parse()?;
            if order.contains(&capability) {
                return Err(ProvisioningResponseError::DuplicateOrder(capability));
            }
            order.push(capability);
        }

        let mut offers = BTreeMap::new();
        for capability in Capability::ALL {
            if let Some(parameters) =
                take_optional::<Map<String, Value>>(&mut fields, capability.as_str())?
            {
                offers.insert(capability, Value::Object(parameters));
            }
        }
        for capability in &order {
            if !offers.contains_key(capability) {
                return Err(ProvisioningResponseError::MissingOffer(*capability));
            }
        }

        Ok(Self {
            provider_info: ProviderInfo {
                enabler_name,
                service_name,
                isp_name,
            },
            ttl,
            token,
            auth,
            order,
            ipv6_mostly,
            offers,
        })
    }

    pub fn select(&self, supported: &[Capability]) -> Option<SelectedOffer<'_>> {
        for &capability in self.order() {
            if !supported.contains(&capability) {
                continue;
            }

            let Some(parameters) = self.offer(capability) else {
                continue;
            };

            return Some(SelectedOffer {
                capability,
                parameters,
            });
        }

        None
    }

    pub fn provider_info(&self) -> &ProviderInfo {
        &self.provider_info
    }

    pub fn ttl(&self) -> Option<Ttl> {
        self.ttl
    }

    pub fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }

    pub fn auth(&self) -> Option<AuthStatus> {
        self.auth
    }

    pub fn order(&self) -> &[Capability] {
        &self.order
    }

    pub fn ipv6_mostly(&self) -> Option<bool> {
        self.ipv6_mostly
    }

    pub fn offer(&self, capability: Capability) -> Option<&Value> {
        self.offers.get(&capability)
    }
}

fn take_required<T>(
    fields: &mut Map<String, Value>,
    field: &'static str,
) -> Result<T, ProvisioningResponseError>
where
    T: DeserializeOwned,
{
    let value = fields
        .remove(field)
        .ok_or(ProvisioningResponseError::MissingField(field))?;
    if value.is_null() {
        return Err(ProvisioningResponseError::NullField(field));
    }

    serde_json::from_value(value)
        .map_err(|source| ProvisioningResponseError::InvalidField { field, source })
}

fn take_optional<T>(
    fields: &mut Map<String, Value>,
    field: &'static str,
) -> Result<Option<T>, ProvisioningResponseError>
where
    T: DeserializeOwned,
{
    let Some(value) = fields.remove(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Err(ProvisioningResponseError::NullField(field));
    }

    serde_json::from_value(value)
        .map(Some)
        .map_err(|source| ProvisioningResponseError::InvalidField { field, source })
}

fn validate_informational_name(
    field: &'static str,
    value: &str,
) -> Result<(), ProvisioningResponseError> {
    if value.len() + 2 > 256 {
        return Err(ProvisioningResponseError::InformationalNameTooLong(field));
    }

    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProvisioningRequestError {
    #[error("at least one capability is required")]
    EmptyCapabilities,
    #[error("capabilities must not contain duplicates")]
    DuplicateCapability,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VendorIdError {
    #[error("vendor ID must be 6 ASCII hex digits with an optional 1..24 character suffix")]
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorId(String);

impl VendorId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for VendorId {
    type Err = VendorIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (oui, suffix) = match value.split_once('-') {
            Some((oui, suffix)) => (oui, Some(suffix)),
            None => (value, None),
        };

        if oui.len() != 6
            || !oui.chars().all(|c| c.is_ascii_hexdigit())
            || suffix.is_some_and(|suffix| {
                suffix.is_empty()
                    || suffix.len() > 24
                    || !suffix
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        {
            return Err(VendorIdError::InvalidFormat);
        }

        Ok(Self(value.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProductError {
    #[error("product must be 1..32 ASCII letters, digits, '_' or '-'")]
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product(String);

impl Product {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Product {
    type Err = ProductError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 32
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ProductError::InvalidFormat);
        }

        Ok(Self(value.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FirmwareVersionError {
    #[error("firmware version must be 1..32 ASCII digits or '_'")]
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareVersion(String);

impl FirmwareVersion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for FirmwareVersion {
    type Err = FirmwareVersionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 32
            || !value.chars().all(|c| c.is_ascii_digit() || c == '_')
        {
            return Err(FirmwareVersionError::InvalidFormat);
        }

        Ok(Self(value.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CredentialsError {
    #[error("user must be at most 32 ASCII letters, digits, '_' or '-'")]
    InvalidUser,
    #[error("password must be at most 32 ASCII letters, digits, '_' or '-'")]
    InvalidPassword,
    #[error("expected server name is not a valid URL host")]
    InvalidExpectedServerName,
}

#[derive(Clone)]
pub struct Credentials {
    user: String,
    password: String,
    expected_server_name: Option<Host<String>>,
}

impl Credentials {
    pub fn new(
        user: String,
        password: String,
        expected_server_name: Option<String>,
    ) -> Result<Self, CredentialsError> {
        if !valid_credential_component(&user) {
            return Err(CredentialsError::InvalidUser);
        }
        if !valid_credential_component(&password) {
            return Err(CredentialsError::InvalidPassword);
        }

        let expected_server_name = expected_server_name
            .map(|server_name| Host::parse(&server_name))
            .transpose()
            .map_err(|_| CredentialsError::InvalidExpectedServerName)?;

        Ok(Self {
            user,
            password,
            expected_server_name,
        })
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("user", &self.user)
            .field("password", &"[redacted]")
            .field("expected_server_name", &self.expected_server_name)
            .finish()
    }
}

fn valid_credential_component(value: &str) -> bool {
    value.len() <= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token must be lowercase ASCII hexadecimal only, 64 characters long")]
    InvalidFormat,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([redacted])")
    }
}

impl FromStr for Token {
    type Err = TokenError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            return Err(TokenError::InvalidFormat);
        }

        Ok(Self(value.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProvisioningUrlError {
    #[error("credentials with an expected server name require HTTPS")]
    CredentialsRequireHttps,
    #[error("credentials with an expected server name require certificate validation")]
    CredentialsRequireCertificateValidation,
    #[error("bootstrap URL host does not match the expected server name")]
    UnexpectedBootstrapHost,
}

#[derive(Clone)]
pub struct ProvisioningRequest {
    vendor_id: VendorId,
    product: Product,
    version: FirmwareVersion,
    capabilities: Vec<Capability>,
    token: Option<Token>,
    credentials: Option<Credentials>,
}

impl ProvisioningRequest {
    pub fn new(
        vendor_id: VendorId,
        product: Product,
        version: FirmwareVersion,
        capabilities: Vec<Capability>,
        token: Option<Token>,
        credentials: Option<Credentials>,
    ) -> Result<Self, ProvisioningRequestError> {
        if capabilities.is_empty() {
            return Err(ProvisioningRequestError::EmptyCapabilities);
        }
        if capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| capabilities[..index].contains(capability))
        {
            return Err(ProvisioningRequestError::DuplicateCapability);
        }

        Ok(Self {
            vendor_id,
            product,
            version,
            capabilities,
            token,
            credentials,
        })
    }

    pub fn vendor_id(&self) -> &VendorId {
        &self.vendor_id
    }

    pub fn product(&self) -> &Product {
        &self.product
    }

    pub fn version(&self) -> &FirmwareVersion {
        &self.version
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_ref().map(Token::as_str)
    }

    pub fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }
}

impl fmt::Debug for ProvisioningRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisioningRequest")
            .field("vendor_id", &self.vendor_id)
            .field("product", &self.product)
            .field("version", &self.version)
            .field("capabilities", &self.capabilities)
            .field("token", &self.token)
            .field("credentials", &self.credentials)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The certificate-validation policy declared by an HB46PP bootstrap record.
pub enum TlsPolicy {
    /// Bootstrap field `t=a`: certificate validation is not required.
    NoCertificateValidation, // t=a
    /// Bootstrap field `t=b`: validate the HTTPS server certificate.
    ValidateCertificate, // t=b
}

#[derive(Debug)]
/// A validated HB46PP bootstrap record.
///
/// It contains the provisioning endpoint and TLS policy obtained from a DNS
/// TXT record.
pub struct Bootstrap {
    url: Url,
    host: Host<String>,
    tls_policy: TlsPolicy,
}

impl Bootstrap {
    /// Parses and validates an HB46PP bootstrap TXT record.
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

        let tls_policy = match tls_value {
            "a" => TlsPolicy::NoCertificateValidation,
            "b" => TlsPolicy::ValidateCertificate,
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

        if url.scheme() == "http" && tls_policy == TlsPolicy::ValidateCertificate {
            return Err(BootstrapError::InvalidTlsForHttp);
        }

        let host = url.host().ok_or(BootstrapError::MissingUrlHost)?.to_owned();

        Ok(Bootstrap {
            url,
            host,
            tls_policy,
        })
    }

    /// Builds the provisioning URL for the initial bootstrap endpoint.
    ///
    /// The returned URL preserves endpoint query parameters and adds the
    /// request's HB46PP query parameters.
    pub fn provisioning_url(
        &self,
        request: &ProvisioningRequest,
    ) -> Result<Url, ProvisioningUrlError> {
        let mut request_url = self.url.clone();
        let capabilities = request
            .capabilities()
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(",");
        {
            let mut query = request_url.query_pairs_mut();
            query.append_pair("vendorid", request.vendor_id().as_str());
            query.append_pair("product", request.product().as_str());
            query.append_pair("version", request.version().as_str());
            query.append_pair("capability", &capabilities);
            if let Some(token) = request.token() {
                query.append_pair("token", token);
            }
            if let Some(credentials) = request.credentials() {
                self.validate_credentials(credentials)?;
                query.append_pair("user", credentials.user());
                query.append_pair("pass", credentials.password());
            }
        }
        Ok(request_url)
    }

    fn validate_credentials(&self, credentials: &Credentials) -> Result<(), ProvisioningUrlError> {
        let Some(expected_server_name) = &credentials.expected_server_name else {
            return Ok(());
        };

        if self.url.scheme() != "https" {
            return Err(ProvisioningUrlError::CredentialsRequireHttps);
        }
        if self.tls_policy != TlsPolicy::ValidateCertificate {
            return Err(ProvisioningUrlError::CredentialsRequireCertificateValidation);
        }

        if self.host != expected_server_name.clone() {
            return Err(ProvisioningUrlError::UnexpectedBootstrapHost);
        }

        Ok(())
    }

    /// Returns the TLS policy declared by the bootstrap record.
    pub fn tls_policy(&self) -> TlsPolicy {
        self.tls_policy
    }

    /// Returns the provisioning endpoint from the bootstrap record.
    pub fn endpoint(&self) -> &Url {
        &self.url
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
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn vendor_id() -> VendorId {
        "000000".parse().unwrap()
    }

    fn product() -> Product {
        "dslite-b4".parse().unwrap()
    }

    fn version() -> FirmwareVersion {
        "0_1_0".parse().unwrap()
    }

    fn credentials(expected_server_name: Option<&str>) -> Credentials {
        Credentials::new(
            "user".to_string(),
            "pass".to_string(),
            expected_server_name.map(str::to_string),
        )
        .unwrap()
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

    #[test]
    fn serializes_capabilities_to_hb46pp_wire_names() {
        let names: Vec<_> = Capability::ALL
            .into_iter()
            .map(Capability::as_str)
            .collect();

        assert_eq!(
            names,
            ["464xlat", "dslite", "ipip", "lw4o6", "map_e", "map_t"]
        );
    }

    #[test]
    fn parses_hb46pp_capability_wire_names() {
        for capability in Capability::ALL {
            assert_eq!(capability.as_str().parse(), Ok(capability));
        }
    }

    #[test]
    fn rejects_unknown_capability_wire_names() {
        for name in ["DS-Lite", "wireguard"] {
            let error = name.parse::<Capability>().unwrap_err();

            assert_eq!(error, CapabilityError::UnsupportedName(name.to_string()));
        }
    }

    #[test]
    fn accepts_ttl_at_the_specification_limit() {
        let ttl = Ttl::try_from(604_800).unwrap();

        assert_eq!(ttl.as_secs(), 604_800);
    }

    #[test]
    fn rejects_ttl_above_the_specification_limit() {
        let error = Ttl::try_from(604_801).unwrap_err();

        assert_eq!(error, TtlError::TooLarge);
    }

    #[test]
    fn parses_hb46pp_auth_statuses() {
        for (wire_name, status) in [
            ("req", AuthStatus::Required),
            ("bad", AuthStatus::Rejected),
            ("ok", AuthStatus::Accepted),
        ] {
            assert_eq!(wire_name.parse(), Ok(status));
            assert_eq!(status.as_str(), wire_name);
        }
    }

    #[test]
    fn rejects_unknown_hb46pp_auth_status() {
        let error = "required".parse::<AuthStatus>().unwrap_err();

        assert_eq!(
            error,
            AuthStatusError::UnsupportedStatus("required".to_string())
        );
    }

    #[test]
    fn parses_v6connect_response_shape() {
        let response = ProvisioningResponse::parse(&format!(
            r#"{{
                "ttl": 86400,
                "token": "{TOKEN}",
                "service_name": "v6 コネクト",
                "enabler_name": "v6 コネクト",
                "dslite": {{"aftr": "dslite.v6connect.net"}},
                "order": ["dslite"],
                "future_extension": {{"ignored": true}}
            }}"#
        ))
        .unwrap();

        assert_eq!(response.provider_info().enabler_name(), "v6 コネクト");
        assert_eq!(response.provider_info().service_name(), Some("v6 コネクト"));
        assert_eq!(response.provider_info().isp_name(), None);
        assert_eq!(response.ttl().unwrap().as_secs(), 86_400);
        assert_eq!(response.token().unwrap().as_str(), TOKEN);
        assert_eq!(response.auth(), None);
        assert_eq!(response.order(), [Capability::DsLite]);
        assert_eq!(
            response.offer(Capability::DsLite),
            Some(&serde_json::json!({"aftr": "dslite.v6connect.net"}))
        );
    }

    #[test]
    fn retains_ipv6_mostly_xlat_offer_outside_activation_order() {
        let response = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "ipv6_mostly": true,
                "dslite": {"aftr": "dslite.example"},
                "464xlat": {"nat64prefix": "64:ff9b::/96"}
            }"#,
        )
        .unwrap();

        assert_eq!(response.order(), [Capability::DsLite]);
        assert_eq!(response.ipv6_mostly(), Some(true));
        assert_eq!(
            response.offer(Capability::Xlat464),
            Some(&serde_json::json!({"nat64prefix": "64:ff9b::/96"}))
        );
    }

    #[test]
    fn selects_the_first_server_ordered_supported_offer() {
        let response = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "order": ["map_e", "dslite"],
                "map_e": {"br": "2001:db8::1", "rules": []},
                "dslite": {"aftr": "dslite.example"}
            }"#,
        )
        .unwrap();

        let selected = response
            .select(&[Capability::DsLite, Capability::MapE])
            .unwrap();

        assert_eq!(selected.capability(), Capability::MapE);
        assert_eq!(
            selected.parameters(),
            &serde_json::json!({"br": "2001:db8::1", "rules": []})
        );
    }

    #[test]
    fn selects_a_later_offer_when_higher_priority_offers_are_unsupported() {
        let response = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "order": ["map_e", "dslite"],
                "map_e": {"br": "2001:db8::1", "rules": []},
                "dslite": {"aftr": "dslite.example"}
            }"#,
        )
        .unwrap();

        let selected = response.select(&[Capability::DsLite]).unwrap();

        assert_eq!(selected.capability(), Capability::DsLite);
        assert_eq!(
            selected.parameters(),
            &serde_json::json!({"aftr": "dslite.example"})
        );
    }

    #[test]
    fn selects_nothing_when_no_ordered_offer_is_supported() {
        let response = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "order": ["map_e"],
                "map_e": {"br": "2001:db8::1", "rules": []}
            }"#,
        )
        .unwrap();

        assert!(response.select(&[Capability::DsLite]).is_none());
    }

    #[test]
    fn rejects_null_for_an_optional_response_field() {
        let error = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "token": null,
                "order": []
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningResponseError::NullField("token")
        ));
    }

    #[test]
    fn rejects_non_object_method_payload() {
        let error = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": "invalid"
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningResponseError::InvalidField {
                field: "dslite",
                ..
            }
        ));
    }

    #[test]
    fn rejects_an_ordered_capability_without_a_payload() {
        let error = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"]
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningResponseError::MissingOffer(Capability::DsLite)
        ));
    }

    #[test]
    fn validates_ttl_and_token_in_a_response() {
        let ttl_error = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "ttl": 604801,
                "order": []
            }"#,
        )
        .unwrap_err();
        let token_error = ProvisioningResponse::parse(
            r#"{
                "enabler_name": "example",
                "token": "not-a-token",
                "order": []
            }"#,
        )
        .unwrap_err();

        assert!(matches!(ttl_error, ProvisioningResponseError::Ttl(_)));
        assert!(matches!(token_error, ProvisioningResponseError::Token(_)));
    }

    #[test]
    fn builds_valid_provisioning_request() {
        let request = valid_request();

        assert_eq!(request.vendor_id().as_str(), "000000");
        assert_eq!(request.product().as_str(), "dslite-b4");
        assert_eq!(request.version().as_str(), "0_1_0");
        assert_eq!(request.capabilities(), [Capability::DsLite]);
        assert_eq!(request.token(), None);
    }

    #[test]
    fn accepts_multiple_capabilities_and_a_token() {
        let request = ProvisioningRequest::new(
            "acde48-v6pc_swg_hgw".parse().unwrap(),
            "V6MIG-ROUTER".parse().unwrap(),
            "1_32".parse().unwrap(),
            vec![Capability::MapE, Capability::DsLite, Capability::Lw4o6],
            Some(TOKEN.parse().unwrap()),
            None,
        )
        .unwrap();

        assert_eq!(
            request.capabilities(),
            [Capability::MapE, Capability::DsLite, Capability::Lw4o6]
        );
        assert_eq!(request.token(), Some(TOKEN));
    }

    #[test]
    fn parses_valid_token() {
        let token: Token = TOKEN.parse().unwrap();

        assert_eq!(token.as_str(), TOKEN);
    }

    #[test]
    fn rejects_invalid_token_formats() {
        let invalid_tokens = [
            "0".repeat(63),
            "0".repeat(65),
            format!("A{}", "0".repeat(63)),
            format!("g{}", "0".repeat(63)),
        ];

        for token in invalid_tokens {
            let error = token.parse::<Token>().unwrap_err();

            assert_eq!(error, TokenError::InvalidFormat);
        }
    }

    #[test]
    fn redacts_tokens_in_debug_output() {
        let token: Token = TOKEN.parse().unwrap();

        let debug = format!("{token:?}");

        assert_eq!(debug, "Token([redacted])");
    }

    #[test]
    fn rejects_invalid_credentials() {
        let invalid_user =
            Credentials::new("user!".to_string(), "pass".to_string(), None).unwrap_err();
        let invalid_password =
            Credentials::new("user".to_string(), "pass!".to_string(), None).unwrap_err();
        let invalid_server_name = Credentials::new(
            "user".to_string(),
            "pass".to_string(),
            Some("[2001:db8::1".to_string()),
        )
        .unwrap_err();

        assert_eq!(invalid_user, CredentialsError::InvalidUser);
        assert_eq!(invalid_password, CredentialsError::InvalidPassword);
        assert_eq!(
            invalid_server_name,
            CredentialsError::InvalidExpectedServerName
        );
    }

    #[test]
    fn rejects_invalid_vendor_id() {
        let error = "not-an-oui".parse::<VendorId>().unwrap_err();

        assert_eq!(error, VendorIdError::InvalidFormat);
    }

    #[test]
    fn rejects_invalid_product() {
        let error = "dslite b4".parse::<Product>().unwrap_err();

        assert_eq!(error, ProductError::InvalidFormat);
    }

    #[test]
    fn rejects_invalid_version() {
        let error = "0.1.0".parse::<FirmwareVersion>().unwrap_err();

        assert_eq!(error, FirmwareVersionError::InvalidFormat);
    }

    #[test]
    fn rejects_empty_capabilities() {
        let error =
            ProvisioningRequest::new(vendor_id(), product(), version(), Vec::new(), None, None)
                .unwrap_err();

        assert_eq!(error, ProvisioningRequestError::EmptyCapabilities);
    }

    #[test]
    fn rejects_duplicate_capabilities() {
        let error = ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::DsLite, Capability::DsLite],
            None,
            None,
        )
        .unwrap_err();

        assert_eq!(error, ProvisioningRequestError::DuplicateCapability);
    }

    #[test]
    fn parses_v6connect_bootstrap_record() {
        let bootstrap = Bootstrap::parse(V6CONNECT_BOOTSTRAP).unwrap();

        assert_eq!(
            bootstrap.endpoint().as_str(),
            "https://prod.v6mig.v6connect.net/cpe/v1/config"
        );
        assert_eq!(bootstrap.tls_policy(), TlsPolicy::ValidateCertificate);
    }

    #[test]
    fn accepts_http_without_tls_validation() {
        let bootstrap = Bootstrap::parse("v=v6mig-1 url=http://vne.example/rule.cgi t=a").unwrap();

        assert_eq!(bootstrap.endpoint().scheme(), "http");
        assert_eq!(bootstrap.tls_policy(), TlsPolicy::NoCertificateValidation);
    }

    #[test]
    fn builds_provisioning_url() {
        let bootstrap = Bootstrap::parse(V6CONNECT_BOOTSTRAP).unwrap();
        let request = valid_request();

        let pairs: Vec<_> = bootstrap
            .provisioning_url(&request)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();

        assert_eq!(
            pairs,
            [
                ("vendorid".to_string(), "000000".to_string()),
                ("product".to_string(), "dslite-b4".to_string()),
                ("version".to_string(), "0_1_0".to_string()),
                ("capability".to_string(), "dslite".to_string()),
            ]
        );
    }

    #[test]
    fn preserves_existing_query_pairs_and_appends_token() {
        let bootstrap =
            Bootstrap::parse("v=v6mig-1 url=https://vne.example/rule.cgi?provider=example t=b")
                .unwrap();
        let request = ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::MapE, Capability::DsLite],
            Some(TOKEN.parse().unwrap()),
            None,
        )
        .unwrap();

        let pairs: Vec<_> = bootstrap
            .provisioning_url(&request)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();

        assert_eq!(
            pairs,
            [
                ("provider".to_string(), "example".to_string()),
                ("vendorid".to_string(), "000000".to_string()),
                ("product".to_string(), "dslite-b4".to_string()),
                ("version".to_string(), "0_1_0".to_string()),
                ("capability".to_string(), "map_e,dslite".to_string()),
                ("token".to_string(), TOKEN.to_string()),
            ]
        );
    }

    #[test]
    fn sends_credentials_without_expected_server_name() {
        let bootstrap = Bootstrap::parse(V6CONNECT_BOOTSTRAP).unwrap();
        let request = ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::DsLite],
            None,
            Some(credentials(None)),
        )
        .unwrap();

        let pairs: Vec<_> = bootstrap
            .provisioning_url(&request)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();

        assert!(pairs.contains(&("user".to_string(), "user".to_string())));
        assert!(pairs.contains(&("pass".to_string(), "pass".to_string())));
    }

    #[test]
    fn sends_credentials_when_expected_server_name_matches_validated_https() {
        let bootstrap = Bootstrap::parse(V6CONNECT_BOOTSTRAP).unwrap();
        let request = ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::DsLite],
            None,
            Some(credentials(Some("prod.v6mig.v6connect.net"))),
        )
        .unwrap();

        assert!(bootstrap.provisioning_url(&request).is_ok());
    }

    #[test]
    fn rejects_credentials_for_unvalidated_or_unexpected_bootstrap() {
        let request_with_expected_server = ProvisioningRequest::new(
            vendor_id(),
            product(),
            version(),
            vec![Capability::DsLite],
            None,
            Some(credentials(Some("provision.example"))),
        )
        .unwrap();
        let http = Bootstrap::parse("v=v6mig-1 url=http://provision.example/rule.cgi t=a").unwrap();
        let unvalidated_https =
            Bootstrap::parse("v=v6mig-1 url=https://provision.example/rule.cgi t=a").unwrap();
        let unexpected_host =
            Bootstrap::parse("v=v6mig-1 url=https://other.example/rule.cgi t=b").unwrap();

        assert_eq!(
            http.provisioning_url(&request_with_expected_server),
            Err(ProvisioningUrlError::CredentialsRequireHttps)
        );
        assert_eq!(
            unvalidated_https.provisioning_url(&request_with_expected_server),
            Err(ProvisioningUrlError::CredentialsRequireCertificateValidation)
        );
        assert_eq!(
            unexpected_host.provisioning_url(&request_with_expected_server),
            Err(ProvisioningUrlError::UnexpectedBootstrapHost)
        );
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
