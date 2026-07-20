use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use thiserror::Error;
use url::{Host, Url};

const V6MIG_SPEC: &str = "v6mig-1";
const MAX_TTL_SECS: u64 = 604_800;

#[derive(Debug, Error)]
#[non_exhaustive]
/// Errors returned when parsing and validating a [`Bootstrap`] record.
pub enum BootstrapError {
    /// The provisioning endpoint is not a supported HTTP or HTTPS URL.
    #[error("url: {0}, err: {1}")]
    InvalidUrl(String, String),
    /// The bootstrap record contains an unsupported `t` value.
    #[error("extracting tls policy : {0}")]
    InvalidTlsPolicy(String),
    /// A bootstrap field does not have its required `key=value` form or order.
    #[error("parsing field, expected: '{0}', got: '{1}'")]
    MalformedField(String, String),
    /// A required bootstrap field is absent.
    #[error("missing field: {0}")]
    MissingField(&'static str),
    /// The bootstrap record declares an unsupported protocol version.
    #[error("unsupported spec version: {0}")]
    UnsupportedVersion(String),
    /// Certificate validation was requested for an HTTP endpoint.
    #[error("tls policy set to validate for http scheme")]
    InvalidTlsForHttp,
    /// The provisioning URL does not contain a host.
    #[error("provisioning URL must contain a host")]
    MissingUrlHost,
    /// The record contains fields beyond the three fields defined by HB46PP.
    #[error("record contain data beyond spec fields, record: {0}")]
    InvalidRecord(String),
    /// The provisioning endpoint uses an IPv4 address instead of IPv6.
    #[error("provisioning URL cannot use an IPv4 address")]
    Ipv4EndpointNotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// An IPv4-over-IPv6 method recognized by HB46PP.
pub enum Capability {
    /// 464XLAT.
    Xlat464,
    /// Dual-Stack Lite.
    DsLite,
    /// An RFC 2473 IP-in-IP tunnel.
    IpIp,
    /// Lightweight 4over6.
    Lw4o6,
    /// Mapping of Address and Port with Encapsulation.
    MapE,
    /// Mapping of Address and Port using Translation.
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

    /// Returns the capability name used in HB46PP requests and responses.
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
/// Errors returned when parsing a [`Capability`] name.
pub enum CapabilityError {
    /// The name is not one of the capabilities defined by HB46PP.
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
/// Errors returned when constructing a provisioning [`Ttl`].
pub enum TtlError {
    /// The lifetime exceeds the protocol maximum of seven days.
    #[error("TTL must be at most {MAX_TTL_SECS} seconds")]
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The validated lifetime of provisioning data, in seconds.
///
/// HB46PP limits this value to seven days.
pub struct Ttl(u32);

impl Ttl {
    /// Returns the provisioning lifetime in seconds.
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
/// The result of user/password authentication reported by the server.
pub enum AuthStatus {
    /// Credentials were absent, but providing them may yield more parameters.
    Required,
    /// Credentials were provided but authentication failed.
    Rejected,
    /// Credentials were provided and authentication succeeded.
    Accepted,
}

impl AuthStatus {
    /// Returns the authentication status value used in an HB46PP response.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "req",
            Self::Rejected => "bad",
            Self::Accepted => "ok",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors returned when parsing an [`AuthStatus`].
pub enum AuthStatusError {
    /// The value is not an authentication status defined by HB46PP.
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
/// Informational names identifying the provisioned service and its providers.
///
/// These names are intended for display. They distinguish the network operator
/// enabling IPv4-over-IPv6 connectivity, that operator's service, and an
/// Internet provider's service offered to customers when all three are supplied.
pub struct ProviderInfo {
    enabler_name: String,
    service_name: Option<String>,
    isp_name: Option<String>,
}

impl ProviderInfo {
    /// Returns the name of the operator enabling IPv4-over-IPv6 connectivity.
    pub fn enabler_name(&self) -> &str {
        &self.enabler_name
    }

    /// Returns that operator's name for the IPv4-over-IPv6 service, if supplied.
    pub fn service_name(&self) -> Option<&str> {
        self.service_name.as_deref()
    }

    /// Returns the Internet provider's service name, if supplied.
    pub fn isp_name(&self) -> Option<&str> {
        self.isp_name.as_deref()
    }
}

/// An offer supported by the caller and selected using the server's preference order.
pub struct SelectedOffer<'a> {
    capability: Capability,
    parameters: &'a serde_json::Value,
}

impl SelectedOffer<'_> {
    /// Returns the IPv4-over-IPv6 method selected for this offer.
    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// Returns the method parameters without interpreting their contents.
    ///
    /// Parameters are a JSON object for every capability except `ipip`, whose
    /// parameters are an array containing one JSON object for each tunnel.
    pub fn parameters(&self) -> &serde_json::Value {
        self.parameters
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
/// Errors returned when parsing and validating [`ProvisioningData`].
pub enum ProvisioningDataError {
    /// The outer JSON value is not an object.
    #[error("response is not a JSON object")]
    NotObject,
    /// A required field is absent from the response.
    #[error("missing required response field: {0}")]
    MissingField(&'static str),
    /// A field is present with `null` instead of its expected value.
    #[error("response field must not be null: {0}")]
    NullField(&'static str),
    /// A field cannot be decoded as its expected JSON type.
    #[error("invalid response field {field}: {source}")]
    InvalidField {
        /// The name of the invalid response field.
        field: &'static str,
        /// The JSON decoding error for the field.
        #[source]
        source: serde_json::Error,
    },
    /// An informational name is too large after JSON encoding.
    #[error("response field exceeds 256 bytes including quotes: {0}")]
    InformationalNameTooLong(&'static str),
    /// The response contains an invalid provisioning lifetime.
    #[error(transparent)]
    Ttl(#[from] TtlError),
    /// The response contains an invalid token.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The response contains an unsupported authentication status.
    #[error(transparent)]
    AuthStatus(#[from] AuthStatusError),
    /// The response names an unsupported capability.
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    /// A capability appears more than once in the server preference order.
    #[error("duplicate capability in response order: {0:?}")]
    DuplicateOrder(Capability),
    /// The preference order names a capability without providing its parameters.
    #[error("response order lists a method without its provisioning payload: {0:?}")]
    MissingOffer(Capability),
    /// A capability's parameters are not in the JSON shape required by HB46PP.
    #[error("invalid provisioning payload shape for capability: {0:?}")]
    InvalidOfferShape(Capability),
}

#[derive(Debug, Clone)]
/// Validated provisioning data returned by an HB46PP server.
///
/// The type validates the shared response fields and retains each method's
/// parameters as JSON for interpretation by the application implementing that
/// method. Unknown fields in the outer object are ignored.
pub struct ProvisioningData {
    provider_info: ProviderInfo,
    ttl: Option<Ttl>,
    token: Option<Token>,
    auth: Option<AuthStatus>,
    order: Vec<Capability>,
    ipv6_mostly: Option<bool>,
    offers: BTreeMap<Capability, Value>,
}

impl ProvisioningData {
    /// Parses and validates an HB46PP provisioning JSON object.
    pub fn parse(input: &str) -> Result<Self, ProvisioningDataError> {
        let value =
            serde_json::from_str(input).map_err(|source| ProvisioningDataError::InvalidField {
                field: "response",
                source,
            })?;
        let mut fields = match value {
            Value::Object(fields) => fields,
            _ => return Err(ProvisioningDataError::NotObject),
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
                return Err(ProvisioningDataError::DuplicateOrder(capability));
            }
            order.push(capability);
        }

        let mut offers = BTreeMap::new();
        for capability in Capability::ALL {
            let Some(parameters) = take_optional::<Value>(&mut fields, capability.as_str())? else {
                continue;
            };

            let has_valid_shape = match capability {
                Capability::IpIp => parameters
                    .as_array()
                    .is_some_and(|tunnels| tunnels.iter().all(Value::is_object)),
                _ => parameters.is_object(),
            };

            if !has_valid_shape {
                return Err(ProvisioningDataError::InvalidOfferShape(capability));
            }

            offers.insert(capability, parameters);
        }
        for capability in &order {
            if !offers.contains_key(capability) {
                return Err(ProvisioningDataError::MissingOffer(*capability));
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

    /// Selects the first supported offer in the server's preference order.
    ///
    /// The order of `supported` does not affect selection. If none of the
    /// server's ordered offers are supported, this returns `None`.
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

    /// Returns the informational service and provider names.
    pub fn provider_info(&self) -> &ProviderInfo {
        &self.provider_info
    }

    /// Returns how long the provisioning data remains valid, if supplied.
    pub fn ttl(&self) -> Option<Ttl> {
        self.ttl
    }

    /// Returns the opaque token for a later provisioning request, if supplied.
    ///
    /// The token is sensitive and should not be logged. It must not be
    /// persisted when the HTTP response prohibits storage.
    pub fn token(&self) -> Option<&Token> {
        self.token.as_ref()
    }

    /// Returns the server's user/password authentication result, if supplied.
    pub fn auth(&self) -> Option<AuthStatus> {
        self.auth
    }

    /// Returns the server's capability preference order.
    pub fn order(&self) -> &[Capability] {
        &self.order
    }

    /// Returns whether the router should provide an IPv6-Mostly local network.
    ///
    /// In this mode, local devices primarily use IPv6 and obtain IPv4
    /// connectivity through 464XLAT. When this is `Some(true)`, the `464xlat`
    /// offer supplies the NAT64 prefix to advertise to the local network even
    /// if `464xlat` is absent from the preference order.
    pub fn ipv6_mostly(&self) -> Option<bool> {
        self.ipv6_mostly
    }

    /// Returns the uninterpreted parameters offered for a capability.
    ///
    /// An offer may be present even when the capability is not listed in the
    /// server preference order, as required for IPv6-Mostly provisioning.
    pub fn offer(&self, capability: Capability) -> Option<&Value> {
        self.offers.get(&capability)
    }
}

fn take_required<T>(
    fields: &mut Map<String, Value>,
    field: &'static str,
) -> Result<T, ProvisioningDataError>
where
    T: DeserializeOwned,
{
    let value = fields
        .remove(field)
        .ok_or(ProvisioningDataError::MissingField(field))?;
    if value.is_null() {
        return Err(ProvisioningDataError::NullField(field));
    }

    serde_json::from_value(value)
        .map_err(|source| ProvisioningDataError::InvalidField { field, source })
}

fn take_optional<T>(
    fields: &mut Map<String, Value>,
    field: &'static str,
) -> Result<Option<T>, ProvisioningDataError>
where
    T: DeserializeOwned,
{
    let Some(value) = fields.remove(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Err(ProvisioningDataError::NullField(field));
    }

    serde_json::from_value(value)
        .map(Some)
        .map_err(|source| ProvisioningDataError::InvalidField { field, source })
}

fn validate_informational_name(
    field: &'static str,
    value: &str,
) -> Result<(), ProvisioningDataError> {
    if value.len() + 2 > 256 {
        return Err(ProvisioningDataError::InformationalNameTooLong(field));
    }

    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors returned when constructing a [`ProvisioningRequest`].
pub enum ProvisioningRequestError {
    /// No supported IPv4-over-IPv6 capability was supplied.
    #[error("at least one capability is required")]
    EmptyCapabilities,
    /// The supplied capability list contains the same capability more than once.
    #[error("capabilities must not contain duplicates")]
    DuplicateCapability,
}

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors returned when parsing a [`VendorId`].
pub enum VendorIdError {
    /// The value does not follow the HB46PP vendor identifier format.
    #[error("vendor ID must be 6 ASCII hex digits with an optional 1..24 character suffix")]
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A validated value for the HB46PP `vendorid` request parameter.
///
/// The value starts with the vendor's 24-bit IEEE organization identifier,
/// written as six hexadecimal digits. It may have a suffix of 1 to 24 ASCII
/// letters, digits, or underscores separated by `-`.
pub struct VendorId(String);

impl VendorId {
    /// Returns the validated vendor identifier.
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
/// Errors returned when parsing a [`Product`].
pub enum ProductError {
    /// The value does not follow the HB46PP product identifier format.
    #[error("product must be 1..32 ASCII letters, digits, '_' or '-'")]
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A validated value for the HB46PP `product` request parameter.
pub struct Product(String);

impl Product {
    /// Returns the validated product identifier.
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
/// Errors returned when parsing a [`FirmwareVersion`].
pub enum FirmwareVersionError {
    /// The value does not follow the HB46PP firmware version format.
    #[error("firmware version must be 1..32 ASCII digits or '_'")]
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A validated value for the HB46PP `version` request parameter.
///
/// Versions contain only ASCII digits and underscores. A dotted software
/// version such as `1.2.0` must therefore be supplied as `1_2_0`.
pub struct FirmwareVersion(String);

impl FirmwareVersion {
    /// Returns the validated firmware version.
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
/// Errors returned when constructing [`Credentials`].
pub enum CredentialsError {
    /// The user name does not follow the HB46PP credential format.
    #[error("user must be at most 32 ASCII letters, digits, '_' or '-'")]
    InvalidUser,
    /// The password does not follow the HB46PP credential format.
    #[error("password must be at most 32 ASCII letters, digits, '_' or '-'")]
    InvalidPassword,
    /// The server name cannot be parsed as a URL host.
    #[error("expected server name is not a valid URL host")]
    InvalidExpectedServerName,
}

#[derive(Clone)]
/// Optional user name and password sent with a provisioning request.
///
/// The custom [`Debug`](fmt::Debug) implementation redacts the password.
pub struct Credentials {
    user: String,
    password: String,
    expected_server_name: Option<Host<String>>,
}

impl Credentials {
    /// Creates credentials restricted to one validated HTTPS server.
    ///
    /// The credentials can only be added to a request when certificate
    /// validation is enabled and the request URL host matches
    /// `expected_server_name`.
    pub fn for_server(
        user: String,
        password: String,
        expected_server_name: String,
    ) -> Result<Self, CredentialsError> {
        validate_credentials(&user, &password)?;

        let expected_server_name = Host::parse(&expected_server_name)
            .map_err(|_| CredentialsError::InvalidExpectedServerName)?;

        Ok(Self {
            user,
            password,
            expected_server_name: Some(expected_server_name),
        })
    }

    /// Creates credentials that may be sent to any provisioning endpoint.
    ///
    /// HB46PP permits this when the user did not provide an expected server
    /// name. This includes endpoints using HTTP, unvalidated HTTPS, and hosts
    /// reached through redirects, so callers must choose this explicitly.
    pub fn unrestricted(user: String, password: String) -> Result<Self, CredentialsError> {
        validate_credentials(&user, &password)?;

        Ok(Self {
            user,
            password,
            expected_server_name: None,
        })
    }

    /// Returns the user name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Returns the password.
    ///
    /// The returned value is sensitive and should not be logged or persisted
    /// without appropriate protection.
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

fn validate_credentials(user: &str, password: &str) -> Result<(), CredentialsError> {
    if !valid_credential_component(user) {
        return Err(CredentialsError::InvalidUser);
    }
    if !valid_credential_component(password) {
        return Err(CredentialsError::InvalidPassword);
    }

    Ok(())
}

fn valid_credential_component(value: &str) -> bool {
    value.len() <= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[derive(Debug, Error, PartialEq, Eq)]
/// Errors returned when parsing a [`Token`].
pub enum TokenError {
    /// The value is not exactly 64 lowercase hexadecimal characters.
    #[error("token must be lowercase ASCII hexadecimal only, 64 characters long")]
    InvalidFormat,
}

#[derive(Clone, PartialEq, Eq)]
/// An opaque token returned by a provisioning server for a later request.
///
/// The custom [`Debug`](fmt::Debug) implementation redacts the token.
pub struct Token(String);

impl Token {
    /// Returns the token value.
    ///
    /// The returned value is sensitive and should not be logged. It must not
    /// be persisted when the provisioning response prohibits storage.
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
/// Errors returned when adding restricted credentials to a provisioning URL.
pub enum ProvisioningUrlError {
    /// Restricted credentials would be sent over a connection without HTTPS.
    #[error("credentials with an expected server name require HTTPS")]
    CredentialsRequireHttps,
    /// Restricted credentials would be sent without certificate validation.
    #[error("credentials with an expected server name require certificate validation")]
    CredentialsRequireCertificateValidation,
    /// The endpoint host does not match the host associated with the credentials.
    #[error("provisioning URL host does not match the expected server name")]
    UnexpectedProvisioningHost,
}

#[derive(Clone)]
/// Validated parameters used to request HB46PP provisioning data.
///
/// The request identifies the device, declares its supported capabilities,
/// and may carry a token or credentials. Its custom [`Debug`](fmt::Debug)
/// implementation redacts those sensitive values.
pub struct ProvisioningRequest {
    vendor_id: VendorId,
    product: Product,
    version: FirmwareVersion,
    capabilities: Vec<Capability>,
    token: Option<Token>,
    credentials: Option<Credentials>,
}

impl ProvisioningRequest {
    /// Creates a provisioning request.
    ///
    /// At least one capability is required, and each capability may appear
    /// only once. The order does not control offer selection; the server's
    /// response order does.
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

    /// Returns the device vendor identifier.
    pub fn vendor_id(&self) -> &VendorId {
        &self.vendor_id
    }

    /// Returns the device product identifier.
    pub fn product(&self) -> &Product {
        &self.product
    }

    /// Returns the device firmware version.
    pub fn version(&self) -> &FirmwareVersion {
        &self.version
    }

    /// Returns the capabilities declared by the device.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Returns the token to send with this request, if present.
    ///
    /// The returned value is sensitive and should not be logged.
    pub fn token(&self) -> Option<&str> {
        self.token.as_ref().map(Token::as_str)
    }

    /// Returns the credentials to send with this request, if present.
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
/// The certificate validation policy declared by an HB46PP bootstrap record.
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

        match url.host() {
            Some(Host::Ipv4(_)) => return Err(BootstrapError::Ipv4EndpointNotAllowed),
            Some(_) => {}
            None => return Err(BootstrapError::MissingUrlHost),
        }

        Ok(Bootstrap { url, tls_policy })
    }

    /// Builds the provisioning URL for the initial bootstrap endpoint.
    ///
    /// The returned URL preserves endpoint query parameters and adds the
    /// request's HB46PP query parameters.
    pub fn provisioning_url(
        &self,
        request: &ProvisioningRequest,
    ) -> Result<Url, ProvisioningUrlError> {
        self.provisioning_url_for(self.url.clone(), request)
    }

    pub(crate) fn provisioning_url_for(
        &self,
        endpoint: Url,
        request: &ProvisioningRequest,
    ) -> Result<Url, ProvisioningUrlError> {
        if let Some(credentials) = request.credentials() {
            self.validate_credentials(&endpoint, credentials)?;
        }
        let mut request_url = endpoint;
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
                query.append_pair("user", credentials.user());
                query.append_pair("pass", credentials.password());
            }
        }
        Ok(request_url)
    }

    fn validate_credentials(
        &self,
        endpoint: &Url,
        credentials: &Credentials,
    ) -> Result<(), ProvisioningUrlError> {
        let Some(expected_server_name) = &credentials.expected_server_name else {
            return Ok(());
        };

        if endpoint.scheme() != "https" {
            return Err(ProvisioningUrlError::CredentialsRequireHttps);
        }
        if self.tls_policy != TlsPolicy::ValidateCertificate {
            return Err(ProvisioningUrlError::CredentialsRequireCertificateValidation);
        }

        let endpoint_host = endpoint.host().map(|host| host.to_owned());
        if endpoint_host.as_ref() != Some(expected_server_name) {
            return Err(ProvisioningUrlError::UnexpectedProvisioningHost);
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

    fn credentials_for_server(expected_server_name: &str) -> Credentials {
        Credentials::for_server(
            "user".to_string(),
            "pass".to_string(),
            expected_server_name.to_string(),
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
        let response = ProvisioningData::parse(&format!(
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
        let response = ProvisioningData::parse(
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
        let response = ProvisioningData::parse(
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
        let response = ProvisioningData::parse(
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
        let response = ProvisioningData::parse(
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
        let error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "token": null,
                "order": []
            }"#,
        )
        .unwrap_err();

        assert!(matches!(error, ProvisioningDataError::NullField("token")));
    }

    #[test]
    fn rejects_non_object_method_payload() {
        let error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"],
                "dslite": "invalid"
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningDataError::InvalidOfferShape(Capability::DsLite)
        ));
    }

    #[test]
    fn accepts_ipip_array_payload() {
        let response = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["ipip"],
                "ipip": [{
                    "ipv6_local": "2001:db8:1::1",
                    "ipv6_remote": "2001:db8:2::1",
                    "ipv4": "192.0.2.0/29"
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            response.offer(Capability::IpIp),
            Some(&serde_json::json!([{
                "ipv6_local": "2001:db8:1::1",
                "ipv6_remote": "2001:db8:2::1",
                "ipv4": "192.0.2.0/29"
            }]))
        );
    }

    #[test]
    fn rejects_ipip_object_payload() {
        let error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["ipip"],
                "ipip": {"ipv6_remote": "2001:db8:2::1"}
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningDataError::InvalidOfferShape(Capability::IpIp)
        ));
    }

    #[test]
    fn rejects_non_object_entry_in_ipip_array() {
        let error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["ipip"],
                "ipip": ["invalid"]
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningDataError::InvalidOfferShape(Capability::IpIp)
        ));
    }

    #[test]
    fn rejects_an_ordered_capability_without_a_payload() {
        let error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "order": ["dslite"]
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProvisioningDataError::MissingOffer(Capability::DsLite)
        ));
    }

    #[test]
    fn validates_ttl_and_token_in_a_response() {
        let ttl_error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "ttl": 604801,
                "order": []
            }"#,
        )
        .unwrap_err();
        let token_error = ProvisioningData::parse(
            r#"{
                "enabler_name": "example",
                "token": "not-a-token",
                "order": []
            }"#,
        )
        .unwrap_err();

        assert!(matches!(ttl_error, ProvisioningDataError::Ttl(_)));
        assert!(matches!(token_error, ProvisioningDataError::Token(_)));
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
            Credentials::unrestricted("user!".to_string(), "pass".to_string()).unwrap_err();
        let invalid_password =
            Credentials::unrestricted("user".to_string(), "pass!".to_string()).unwrap_err();
        let invalid_server_name = Credentials::for_server(
            "user".to_string(),
            "pass".to_string(),
            "[2001:db8::1".to_string(),
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
            Some(Credentials::unrestricted("user".to_string(), "pass".to_string()).unwrap()),
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
            Some(credentials_for_server("prod.v6mig.v6connect.net")),
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
            Some(credentials_for_server("provision.example")),
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
            Err(ProvisioningUrlError::UnexpectedProvisioningHost)
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

    #[test]
    fn rejects_ipv4_literal_provisioning_url() {
        let error = Bootstrap::parse("v=v6mig-1 url=https://192.0.2.1/provision t=b").unwrap_err();

        assert!(matches!(error, BootstrapError::Ipv4EndpointNotAllowed));
    }
}
