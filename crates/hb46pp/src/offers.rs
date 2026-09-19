//! Typed HB46PP offers.

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use serde_json::{Map, Value};
use thiserror::Error;

use crate::Capability;

/// Typed offer validation error.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfferError {
    /// Invalid parameter.
    #[error("{path}: {message}")]
    Invalid {
        /// JSON path.
        path: String,
        /// Reason.
        message: String,
    },
}

impl OfferError {
    /// JSON path of the invalid parameter.
    pub fn path(&self) -> &str {
        match self {
            Self::Invalid { path, .. } => path,
        }
    }

    /// Reason the parameter is invalid.
    pub fn message(&self) -> &str {
        match self {
            Self::Invalid { message, .. } => message,
        }
    }
}

fn invalid(path: impl Into<String>, message: impl Into<String>) -> OfferError {
    OfferError::Invalid {
        path: path.into(),
        message: message.into(),
    }
}

/// DNS name parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DnsNameError {
    /// The name is not a valid DNS name.
    #[error("expected a syntactically valid DNS name")]
    InvalidSyntax,
}

/// Tunnel endpoint DNS name.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DnsName(String);

impl DnsName {
    /// Canonical DNS name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DnsName").field(&self.0).finish()
    }
}
impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for DnsName {
    type Err = DnsNameError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let name = value.strip_suffix('.').unwrap_or(value);
        if name.is_empty()
            || name.len() > 253
            || name.parse::<Ipv4Addr>().is_ok()
            || name.parse::<Ipv6Addr>().is_ok()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err(DnsNameError::InvalidSyntax);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
}

/// Tunnel endpoint parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TunnelEndpointError {
    /// IPv4 literals are not valid tunnel endpoints.
    #[error("IPv4 literals are not permitted")]
    Ipv4NotAllowed,
    /// The DNS name is invalid.
    #[error(transparent)]
    InvalidDnsName(#[from] DnsNameError),
}

/// Tunnel endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TunnelEndpoint {
    /// IPv6 literal.
    Ipv6(Ipv6Addr),
    /// DNS name.
    DnsName(DnsName),
}

impl fmt::Display for TunnelEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipv6(address) => address.fmt(f),
            Self::DnsName(name) => name.fmt(f),
        }
    }
}

impl FromStr for TunnelEndpoint {
    type Err = TunnelEndpointError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<Ipv6Addr>() {
            return Ok(Self::Ipv6(address));
        }
        if value.parse::<Ipv4Addr>().is_ok() {
            return Err(TunnelEndpointError::Ipv4NotAllowed);
        }
        Ok(Self::DnsName(value.parse()?))
    }
}

/// IPv4 prefix parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Ipv4PrefixError {
    /// The value is not in CIDR notation.
    #[error("expected an address and prefix length")]
    InvalidFormat,
    /// The address is not IPv4.
    #[error("expected an IPv4 prefix")]
    InvalidAddress,
    /// The prefix length is invalid.
    #[error("invalid prefix length")]
    InvalidPrefixLength,
}

/// IPv4 network prefix. Host bits are zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Prefix {
    address: Ipv4Addr,
    prefix_len: u8,
}
impl Ipv4Prefix {
    /// Network address.
    pub fn address(self) -> Ipv4Addr {
        self.address
    }
    /// Prefix length.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}
impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}
impl FromStr for Ipv4Prefix {
    type Err = Ipv4PrefixError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, len) = parse_cidr(value, 32).map_err(Ipv4PrefixError::from)?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| Ipv4PrefixError::InvalidAddress)?;
        let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
        Ok(Self {
            address: Ipv4Addr::from(u32::from(address) & mask),
            prefix_len: len,
        })
    }
}

/// IPv6 prefix parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Ipv6PrefixError {
    /// The value is not in CIDR notation.
    #[error("expected an address and prefix length")]
    InvalidFormat,
    /// The address is not IPv6.
    #[error("expected an IPv6 prefix")]
    InvalidAddress,
    /// The prefix length is invalid.
    #[error("invalid prefix length")]
    InvalidPrefixLength,
}

/// IPv6 network prefix. Host bits are zeroed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Prefix {
    address: Ipv6Addr,
    prefix_len: u8,
}
impl Ipv6Prefix {
    /// Network address.
    pub fn address(self) -> Ipv6Addr {
        self.address
    }
    /// Prefix length.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}
impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}
impl FromStr for Ipv6Prefix {
    type Err = Ipv6PrefixError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, len) = parse_cidr(value, 128).map_err(Ipv6PrefixError::from)?;
        let address: Ipv6Addr = address
            .parse()
            .map_err(|_| Ipv6PrefixError::InvalidAddress)?;
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - len)
        };
        Ok(Self {
            address: Ipv6Addr::from(u128::from(address) & mask),
            prefix_len: len,
        })
    }
}

/// IPv4 CIDR parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Ipv4CidrError {
    /// The value is not in CIDR notation.
    #[error("expected an address and prefix length")]
    InvalidFormat,
    /// The address is not IPv4.
    #[error("expected an IPv4 CIDR")]
    InvalidAddress,
    /// The prefix length is invalid.
    #[error("invalid prefix length")]
    InvalidPrefixLength,
}

/// IPv4 CIDR assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    address: Ipv4Addr,
    prefix_len: u8,
}
impl Ipv4Cidr {
    /// Address, including host bits.
    pub fn address(self) -> Ipv4Addr {
        self.address
    }
    /// CIDR prefix length.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}
impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}
impl FromStr for Ipv4Cidr {
    type Err = Ipv4CidrError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_len) = parse_cidr(value, 32).map_err(Ipv4CidrError::from)?;
        Ok(Self {
            address: address.parse().map_err(|_| Ipv4CidrError::InvalidAddress)?,
            prefix_len,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CidrError {
    InvalidFormat,
    InvalidPrefixLength,
}

impl From<CidrError> for Ipv4PrefixError {
    fn from(error: CidrError) -> Self {
        match error {
            CidrError::InvalidFormat => Self::InvalidFormat,
            CidrError::InvalidPrefixLength => Self::InvalidPrefixLength,
        }
    }
}

impl From<CidrError> for Ipv6PrefixError {
    fn from(error: CidrError) -> Self {
        match error {
            CidrError::InvalidFormat => Self::InvalidFormat,
            CidrError::InvalidPrefixLength => Self::InvalidPrefixLength,
        }
    }
}

impl From<CidrError> for Ipv4CidrError {
    fn from(error: CidrError) -> Self {
        match error {
            CidrError::InvalidFormat => Self::InvalidFormat,
            CidrError::InvalidPrefixLength => Self::InvalidPrefixLength,
        }
    }
}

fn parse_cidr(value: &str, maximum: u8) -> Result<(&str, u8), CidrError> {
    let (address, length) = value.split_once('/').ok_or(CidrError::InvalidFormat)?;
    if length.contains('/') {
        return Err(CidrError::InvalidFormat);
    }
    if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CidrError::InvalidPrefixLength);
    }
    let length = length
        .parse::<u8>()
        .map_err(|_| CidrError::InvalidPrefixLength)?;
    if length > maximum {
        return Err(CidrError::InvalidPrefixLength);
    }
    Ok((address, length))
}

/// Lightweight 4over6 port set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortSet {
    psid: u16,
    psid_length: u8,
    psid_offset: u8,
}
impl PortSet {
    /// Port-set identifier.
    pub fn psid(self) -> u16 {
        self.psid
    }
    /// PSID width in bits.
    pub fn psid_length(self) -> u8 {
        self.psid_length
    }
    /// PSID offset in bits.
    pub fn psid_offset(self) -> u8 {
        self.psid_offset
    }
}

/// MAP mapping rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRule {
    ipv6: Ipv6Prefix,
    ipv4: Ipv4Prefix,
    ea_length: u8,
    psid_offset: u8,
}
impl MappingRule {
    /// IPv6 forwarding-mapping-rule prefix.
    pub fn ipv6(&self) -> Ipv6Prefix {
        self.ipv6
    }
    /// IPv4 forwarding-mapping-rule prefix.
    pub fn ipv4(&self) -> Ipv4Prefix {
        self.ipv4
    }
    /// Embedded-address bit length.
    pub fn ea_length(&self) -> u8 {
        self.ea_length
    }
    /// PSID offset.
    pub fn psid_offset(&self) -> u8 {
        self.psid_offset
    }
    /// IPv4 suffix width in bits.
    pub fn ipv4_suffix_length(&self) -> u8 {
        self.ea_length.min(32 - self.ipv4.prefix_len())
    }
    /// Derived PSID width in bits.
    pub fn psid_length(&self) -> u8 {
        self.ea_length.saturating_sub(self.ipv4_suffix_length())
    }
    /// Whether this rule shares IPv4 addresses among multiple CEs.
    pub fn uses_address_sharing(&self) -> bool {
        self.psid_length() != 0
    }
    /// Verifies that a delegated prefix can use this rule.
    pub fn validate_delegated_prefix(
        &self,
        prefix: Ipv6Prefix,
    ) -> Result<(), MappingRulePrefixError> {
        if prefix.prefix_len() < self.ipv6.prefix_len() + self.ea_length {
            return Err(MappingRulePrefixError::TooShort);
        }
        let rule_mask = if self.ipv6.prefix_len() == 0 {
            0
        } else {
            u128::MAX << (128 - self.ipv6.prefix_len())
        };
        if u128::from(prefix.address()) & rule_mask != u128::from(self.ipv6.address()) {
            return Err(MappingRulePrefixError::OutsideRule);
        }
        Ok(())
    }
}

/// Delegated prefix validation error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MappingRulePrefixError {
    /// The delegated prefix is outside the mapping-rule prefix.
    #[error("delegated prefix is outside the mapping-rule IPv6 prefix")]
    OutsideRule,
    /// The delegated prefix has insufficient EA bits.
    #[error("delegated prefix is too short for the mapping-rule EA bits")]
    TooShort,
}

/// 464XLAT parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xlat464Parameters {
    nat64_prefix: Ipv6Prefix,
}
impl Xlat464Parameters {
    /// NAT64 PREF64 prefix.
    pub fn nat64_prefix(&self) -> Ipv6Prefix {
        self.nat64_prefix
    }
}

/// DS-Lite parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsLiteParameters {
    aftr: TunnelEndpoint,
}
impl DsLiteParameters {
    /// AFTR endpoint.
    pub fn aftr(&self) -> &TunnelEndpoint {
        &self.aftr
    }
}

/// IP-in-IP tunnel assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpIpTunnel {
    local: Ipv6Addr,
    remote: Ipv6Addr,
    ipv4: Ipv4Cidr,
}
impl IpIpTunnel {
    /// CPE IPv6 tunnel address.
    pub fn local(&self) -> Ipv6Addr {
        self.local
    }
    /// Provider IPv6 tunnel address.
    pub fn remote(&self) -> Ipv6Addr {
        self.remote
    }
    /// IPv4 CIDR assignment.
    pub fn ipv4(&self) -> Ipv4Cidr {
        self.ipv4
    }
}

/// IP-in-IP parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpIpParameters {
    tunnels: Vec<IpIpTunnel>,
}
impl IpIpParameters {
    /// Tunnel assignments.
    pub fn tunnels(&self) -> &[IpIpTunnel] {
        &self.tunnels
    }
}

/// Lightweight 4over6 parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lw4o6Parameters {
    lwaftr: TunnelEndpoint,
    binding_prefix: Ipv6Prefix,
    public_ipv4_address: Ipv4Addr,
    port_set: PortSet,
}
impl Lw4o6Parameters {
    /// lwAFTR endpoint.
    pub fn lwaftr(&self) -> &TunnelEndpoint {
        &self.lwaftr
    }
    /// IPv6 binding prefix.
    pub fn binding_prefix(&self) -> Ipv6Prefix {
        self.binding_prefix
    }
    /// NAPT44 public IPv4 address.
    pub fn public_ipv4_address(&self) -> Ipv4Addr {
        self.public_ipv4_address
    }
    /// Port set.
    pub fn port_set(&self) -> PortSet {
        self.port_set
    }
}

/// MAP-E version.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MapEVersion {
    /// draft-ietf-softwire-map-03 (`0`).
    #[default]
    Draft03,
    /// RFC 7597 (`1`).
    Rfc7597,
}

/// MAP-E version parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MapEVersionError {
    /// The wire value is unsupported.
    #[error("unsupported MAP-E version: {0}")]
    UnsupportedValue(String),
}

impl fmt::Display for MapEVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Draft03 => "0",
            Self::Rfc7597 => "1",
        })
    }
}

impl FromStr for MapEVersion {
    type Err = MapEVersionError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "0" => Ok(Self::Draft03),
            "1" => Ok(Self::Rfc7597),
            _ => Err(MapEVersionError::UnsupportedValue(value.to_string())),
        }
    }
}

/// MAP forwarding mode parsing error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MapModeError {
    /// The wire value is unsupported.
    #[error("unsupported MAP mode: {0}")]
    UnsupportedValue(String),
}

/// MAP-E forwarding mode.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MapMode {
    /// CE-to-BR only.
    #[default]
    HubAndSpoke,
    /// CE-to-BR and CE-to-CE.
    Mesh,
}

impl fmt::Display for MapMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HubAndSpoke => "0",
            Self::Mesh => "1",
        })
    }
}

impl FromStr for MapMode {
    type Err = MapModeError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "0" | "false" => Ok(Self::HubAndSpoke),
            "1" | "true" => Ok(Self::Mesh),
            _ => Err(MapModeError::UnsupportedValue(value.to_string())),
        }
    }
}

/// MAP-E parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapEParameters {
    version: MapEVersion,
    mode: MapMode,
    br: Ipv6Addr,
    rules: Vec<MappingRule>,
}
impl MapEParameters {
    /// MAP-E version.
    pub fn version(&self) -> MapEVersion {
        self.version
    }
    /// MAP-E mode.
    pub fn mode(&self) -> MapMode {
        self.mode
    }
    /// Border-relay IPv6 address.
    pub fn br(&self) -> Ipv6Addr {
        self.br
    }
    /// Mapping rules.
    pub fn rules(&self) -> &[MappingRule] {
        &self.rules
    }
}

/// MAP-T parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapTParameters {
    dmr: Ipv6Prefix,
    rules: Vec<MappingRule>,
}
impl MapTParameters {
    /// Default mapping rule prefix.
    pub fn dmr(&self) -> Ipv6Prefix {
        self.dmr
    }
    /// Mapping rules.
    pub fn rules(&self) -> &[MappingRule] {
        &self.rules
    }
}

/// Validated HB46PP offer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisioningOffer {
    /// 464XLAT parameters.
    Xlat464(Xlat464Parameters),
    /// DS-Lite parameters.
    DsLite(DsLiteParameters),
    /// IP-in-IP parameters.
    IpIp(IpIpParameters),
    /// Lightweight 4over6 parameters.
    Lw4o6(Lw4o6Parameters),
    /// MAP-E parameters.
    MapE(MapEParameters),
    /// MAP-T parameters.
    MapT(MapTParameters),
}
impl ProvisioningOffer {
    /// Offer capability.
    pub fn capability(&self) -> Capability {
        match self {
            Self::Xlat464(_) => Capability::Xlat464,
            Self::DsLite(_) => Capability::DsLite,
            Self::IpIp(_) => Capability::IpIp,
            Self::Lw4o6(_) => Capability::Lw4o6,
            Self::MapE(_) => Capability::MapE,
            Self::MapT(_) => Capability::MapT,
        }
    }
    /// 464XLAT parameters.
    pub fn as_xlat464(&self) -> Option<&Xlat464Parameters> {
        if let Self::Xlat464(value) = self {
            Some(value)
        } else {
            None
        }
    }
    /// DS-Lite parameters.
    pub fn as_dslite(&self) -> Option<&DsLiteParameters> {
        if let Self::DsLite(value) = self {
            Some(value)
        } else {
            None
        }
    }
    /// IP-in-IP parameters.
    pub fn as_ipip(&self) -> Option<&IpIpParameters> {
        if let Self::IpIp(value) = self {
            Some(value)
        } else {
            None
        }
    }
    /// Lightweight 4over6 parameters.
    pub fn as_lw4o6(&self) -> Option<&Lw4o6Parameters> {
        if let Self::Lw4o6(value) = self {
            Some(value)
        } else {
            None
        }
    }
    /// MAP-E parameters.
    pub fn as_map_e(&self) -> Option<&MapEParameters> {
        if let Self::MapE(value) = self {
            Some(value)
        } else {
            None
        }
    }
    /// MAP-T parameters.
    pub fn as_map_t(&self) -> Option<&MapTParameters> {
        if let Self::MapT(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn parse(capability: Capability, value: &Value) -> Result<Self, OfferError> {
        match capability {
            Capability::Xlat464 => {
                let fields = object(value, "464xlat")?;
                let prefix = prefix6(
                    required_string(fields, "nat64prefix", "464xlat")?,
                    "464xlat.nat64prefix",
                )?;
                if !matches!(prefix.prefix_len(), 32 | 40 | 48 | 56 | 64 | 96) {
                    return Err(invalid(
                        "464xlat.nat64prefix",
                        "NAT64 prefix length must be one of 32, 40, 48, 56, 64, or 96",
                    ));
                }
                Ok(ProvisioningOffer::Xlat464(Xlat464Parameters {
                    nat64_prefix: prefix,
                }))
            }
            Capability::DsLite => {
                let fields = object(value, "dslite")?;
                Ok(ProvisioningOffer::DsLite(DsLiteParameters {
                    aftr: endpoint(required_string(fields, "aftr", "dslite")?, "dslite.aftr")?,
                }))
            }
            Capability::IpIp => {
                let tunnels = value
                    .as_array()
                    .ok_or_else(|| invalid("ipip", "expected an array"))?;
                let mut parsed = Vec::with_capacity(tunnels.len());
                for (index, tunnel) in tunnels.iter().enumerate() {
                    let path = format!("ipip[{index}]");
                    let fields = object(tunnel, &path)?;
                    parsed.push(IpIpTunnel {
                        local: address6(
                            required_string(fields, "ipv6_local", &path)?,
                            &format!("{path}.ipv6_local"),
                        )?,
                        remote: address6(
                            required_string(fields, "ipv6_remote", &path)?,
                            &format!("{path}.ipv6_remote"),
                        )?,
                        ipv4: cidr4(
                            required_string(fields, "ipv4", &path)?,
                            &format!("{path}.ipv4"),
                        )?,
                    });
                }
                Ok(ProvisioningOffer::IpIp(IpIpParameters { tunnels: parsed }))
            }
            Capability::Lw4o6 => {
                let fields = object(value, "lw4o6")?;
                let psid_offset = number(fields, "psid_offset", "lw4o6", 15)? as u8;
                let psid_length = number(fields, "psid_length", "lw4o6", 16)? as u8;
                if psid_length > 16 - psid_offset {
                    return Err(invalid(
                        "lw4o6.psid_length",
                        "PSID length exceeds the available port bits",
                    ));
                }
                let psid = number(fields, "psid", "lw4o6", u16::MAX as u64)? as u16;
                if (psid_length == 0 && psid != 0)
                    || (psid_length < 16 && u32::from(psid) >= (1_u32 << psid_length))
                {
                    return Err(invalid(
                        "lw4o6.psid",
                        "PSID is not representable in psid_length bits",
                    ));
                }
                Ok(ProvisioningOffer::Lw4o6(Lw4o6Parameters {
                    lwaftr: endpoint(required_string(fields, "lwaftr", "lw4o6")?, "lw4o6.lwaftr")?,
                    binding_prefix: prefix6(
                        required_string(fields, "ipv6", "lw4o6")?,
                        "lw4o6.ipv6",
                    )?,
                    public_ipv4_address: address4(
                        required_string(fields, "ipv4", "lw4o6")?,
                        "lw4o6.ipv4",
                    )?,
                    port_set: PortSet {
                        psid,
                        psid_length,
                        psid_offset,
                    },
                }))
            }
            Capability::MapE => {
                let fields = object(value, "map_e")?;
                let version = match optional(fields, "version", "map_e")? {
                    None => MapEVersion::Draft03,
                    Some(Value::Number(number)) if number.as_u64() == Some(0) => {
                        MapEVersion::Draft03
                    }
                    Some(Value::Number(number)) if number.as_u64() == Some(1) => {
                        MapEVersion::Rfc7597
                    }
                    _ => return Err(invalid("map_e.version", "expected 0 or 1")),
                };
                let mode = match optional(fields, "mesh", "map_e")? {
                    None | Some(Value::Bool(false)) => MapMode::HubAndSpoke,
                    Some(Value::Bool(true)) => MapMode::Mesh,
                    Some(Value::Number(number)) if number.as_u64() == Some(0) => {
                        MapMode::HubAndSpoke
                    }
                    Some(Value::Number(number)) if number.as_u64() == Some(1) => MapMode::Mesh,
                    _ => return Err(invalid("map_e.mesh", "expected a boolean or 0 or 1")),
                };
                Ok(ProvisioningOffer::MapE(MapEParameters {
                    version,
                    mode,
                    br: address6(required_string(fields, "br", "map_e")?, "map_e.br")?,
                    rules: rules(fields, "map_e", 256)?,
                }))
            }
            Capability::MapT => {
                let fields = object(value, "map_t")?;
                let dmr = prefix6(required_string(fields, "dmr", "map_t")?, "map_t.dmr")?;
                if dmr.prefix_len() > 96 {
                    return Err(invalid(
                        "map_t.dmr",
                        "DMR prefix length must not exceed 96 bits",
                    ));
                }
                Ok(ProvisioningOffer::MapT(MapTParameters {
                    dmr,
                    rules: rules(fields, "map_t", 200)?,
                }))
            }
        }
    }
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, OfferError> {
    value
        .as_object()
        .ok_or_else(|| invalid(path, "expected an object"))
}
fn optional<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
    path: &str,
) -> Result<Option<&'a Value>, OfferError> {
    match fields.get(name) {
        Some(Value::Null) => Err(invalid(format!("{path}.{name}"), "must not be null")),
        value => Ok(value),
    }
}
fn required<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
    path: &str,
) -> Result<&'a Value, OfferError> {
    optional(fields, name, path)?.ok_or_else(|| invalid(format!("{path}.{name}"), "is required"))
}
fn required_string<'a>(
    fields: &'a Map<String, Value>,
    name: &str,
    path: &str,
) -> Result<&'a str, OfferError> {
    required(fields, name, path)?
        .as_str()
        .ok_or_else(|| invalid(format!("{path}.{name}"), "expected a string"))
}
fn number(
    fields: &Map<String, Value>,
    name: &str,
    path: &str,
    max: u64,
) -> Result<u64, OfferError> {
    let value = required(fields, name, path)?
        .as_u64()
        .ok_or_else(|| invalid(format!("{path}.{name}"), "expected a non-negative integer"))?;
    if value > max {
        return Err(invalid(
            format!("{path}.{name}"),
            "is outside the permitted range",
        ));
    }
    Ok(value)
}
fn address4(value: &str, path: &str) -> Result<Ipv4Addr, OfferError> {
    value
        .parse()
        .map_err(|_| invalid(path, "expected an IPv4 address"))
}
fn address6(value: &str, path: &str) -> Result<Ipv6Addr, OfferError> {
    value
        .parse()
        .map_err(|_| invalid(path, "expected an IPv6 address"))
}
fn endpoint(value: &str, path: &str) -> Result<TunnelEndpoint, OfferError> {
    value
        .parse()
        .map_err(|error: TunnelEndpointError| invalid(path, error.to_string()))
}
fn prefix4(value: &str, path: &str) -> Result<Ipv4Prefix, OfferError> {
    value
        .parse()
        .map_err(|error: Ipv4PrefixError| invalid(path, error.to_string()))
}
fn prefix6(value: &str, path: &str) -> Result<Ipv6Prefix, OfferError> {
    value
        .parse()
        .map_err(|error: Ipv6PrefixError| invalid(path, error.to_string()))
}
fn cidr4(value: &str, path: &str) -> Result<Ipv4Cidr, OfferError> {
    value
        .parse()
        .map_err(|error: Ipv4CidrError| invalid(path, error.to_string()))
}
fn rules(
    fields: &Map<String, Value>,
    path: &str,
    max: usize,
) -> Result<Vec<MappingRule>, OfferError> {
    let values = required(fields, "rules", path)?
        .as_array()
        .ok_or_else(|| invalid(format!("{path}.rules"), "expected an array"))?;
    if values.is_empty() || values.len() > max {
        return Err(invalid(
            format!("{path}.rules"),
            format!("must contain from 1 through {max} rules"),
        ));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let item_path = format!("{path}.rules[{index}]");
            let item = object(value, &item_path)?;
            let ipv6 = prefix6(
                required_string(item, "ipv6", &item_path)?,
                &format!("{item_path}.ipv6"),
            )?;
            let ipv4 = prefix4(
                required_string(item, "ipv4", &item_path)?,
                &format!("{item_path}.ipv4"),
            )?;
            let ea_length = number(item, "ea_length", &item_path, 48)? as u8;
            let psid_offset = number(item, "psid_offset", &item_path, 15)? as u8;
            if u16::from(ipv6.prefix_len()) + u16::from(ea_length) > 128 {
                return Err(invalid(
                    format!("{item_path}.ea_length"),
                    "IPv6 prefix and EA bits exceed 128 bits",
                ));
            }
            let ipv4_suffix_width = 32 - ipv4.prefix_len();
            let psid_width = ea_length.saturating_sub(ipv4_suffix_width);
            if psid_width > 16 {
                return Err(invalid(
                    format!("{item_path}.ea_length"),
                    "derived PSID width must not exceed 16 bits",
                ));
            }
            if psid_offset + psid_width > 16 {
                return Err(invalid(
                    format!("{item_path}.psid_offset"),
                    "PSID offset and derived width exceed the 16-bit port number",
                ));
            }
            Ok(MappingRule {
                ipv6,
                ipv4,
                ea_length,
                psid_offset,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProvisioningData, ProvisioningDataError};
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    const RULE: &str =
        r#"{"ipv6":"2001:db8:1:abcd::/56","ipv4":"203.0.113.7/24","ea_length":12,"psid_offset":4}"#;

    fn valid_rule() -> Value {
        serde_json::json!({
            "ipv6": "2001:db8:1::/56",
            "ipv4": "203.0.113.0/24",
            "ea_length": 12,
            "psid_offset": 4
        })
    }

    fn response(capability: Capability, offer: Value, ordered: bool) -> String {
        let mut fields = Map::new();
        fields.insert("enabler_name".to_string(), Value::String("VNE".to_string()));
        fields.insert(
            "order".to_string(),
            if ordered {
                Value::Array(vec![Value::String(capability.as_str().to_string())])
            } else {
                Value::Array(Vec::new())
            },
        );
        fields.insert(capability.as_str().to_string(), offer);
        Value::Object(fields).to_string()
    }

    fn offer_error(capability: Capability, offer: Value) -> OfferError {
        match ProvisioningData::parse(&response(capability, offer, true)).unwrap_err() {
            ProvisioningDataError::Offer {
                capability: actual,
                source,
            } => {
                assert_eq!(actual, capability);
                source
            }
            error => panic!("expected offer error, got {error:?}"),
        }
    }

    fn assert_error_path(capability: Capability, offer: Value, expected: &str) {
        let OfferError::Invalid { path, .. } = offer_error(capability, offer);
        assert_eq!(path, expected);
    }

    #[test]
    fn dns_names_are_canonicalized_for_equality_and_hashing() {
        let upper: DnsName = "AFTR.Example.".parse().unwrap();
        let lower: DnsName = "aftr.example.".parse().unwrap();
        assert_eq!(upper.as_str(), "aftr.example.");
        assert_eq!(upper, lower);

        let mut upper_hash = DefaultHasher::new();
        upper.hash(&mut upper_hash);
        let mut lower_hash = DefaultHasher::new();
        lower.hash(&mut lower_hash);
        assert_eq!(upper_hash.finish(), lower_hash.finish());
    }

    #[test]
    fn scalar_types_report_dedicated_parse_errors() {
        assert_eq!(
            "bad..name".parse::<DnsName>(),
            Err(DnsNameError::InvalidSyntax)
        );
        assert_eq!(
            "192.0.2.1".parse::<TunnelEndpoint>(),
            Err(TunnelEndpointError::Ipv4NotAllowed)
        );
        assert_eq!(
            "bad..name".parse::<TunnelEndpoint>(),
            Err(TunnelEndpointError::InvalidDnsName(
                DnsNameError::InvalidSyntax
            ))
        );
        assert_eq!(
            "192.0.2.1".parse::<Ipv4Prefix>(),
            Err(Ipv4PrefixError::InvalidFormat)
        );
        assert_eq!(
            "2001:db8::/24".parse::<Ipv4Prefix>(),
            Err(Ipv4PrefixError::InvalidAddress)
        );
        assert_eq!(
            "192.0.2.0/33".parse::<Ipv4Prefix>(),
            Err(Ipv4PrefixError::InvalidPrefixLength)
        );
        assert_eq!(
            "2001:db8::/129".parse::<Ipv6Prefix>(),
            Err(Ipv6PrefixError::InvalidPrefixLength)
        );
        assert_eq!(
            "2001:db8::/24".parse::<Ipv4Cidr>(),
            Err(Ipv4CidrError::InvalidAddress)
        );
        assert_eq!(
            "2".parse::<MapEVersion>(),
            Err(MapEVersionError::UnsupportedValue("2".to_string()))
        );
        assert_eq!(
            "invalid".parse::<MapMode>(),
            Err(MapModeError::UnsupportedValue("invalid".to_string()))
        );
    }

    #[test]
    fn offer_errors_expose_path_and_message() {
        let error = offer_error(Capability::DsLite, serde_json::json!({"aftr": "bad..name"}));
        assert_eq!(error.path(), "dslite.aftr");
        assert_eq!(error.message(), "expected a syntactically valid DNS name");
    }

    #[test]
    fn parses_all_typed_offers_and_normalizes_prefixes() {
        let data = ProvisioningData::parse(&format!(r#"{{
            "enabler_name":"VNE", "order":["464xlat","dslite","ipip","lw4o6","map_e","map_t"],
            "464xlat":{{"nat64prefix":"64:ff9b::1/96"}},
            "dslite":{{"aftr":"2001:db8::1"}},
            "ipip":[{{"ipv6_local":"2001:db8::2","ipv6_remote":"2001:db8::3","ipv4":"192.0.2.4/29"}}],
            "lw4o6":{{"lwaftr":"lwaftr.example","ipv6":"2001:db8:3:1234::/56","ipv4":"203.0.113.16","psid":3,"psid_length":8,"psid_offset":6}},
            "map_e":{{"br":"2001:db8::4","rules":[{RULE}]}},
            "map_t":{{"dmr":"2001:db8:5::1/64","rules":[{RULE}]}}
        }}"#)).unwrap();
        assert_eq!(
            data.offer(Capability::Xlat464)
                .unwrap()
                .as_xlat464()
                .unwrap()
                .nat64_prefix()
                .to_string(),
            "64:ff9b::/96"
        );
        assert_eq!(
            data.offer(Capability::IpIp)
                .unwrap()
                .as_ipip()
                .unwrap()
                .tunnels()[0]
                .ipv4()
                .to_string(),
            "192.0.2.4/29"
        );
        assert_eq!(
            data.offer(Capability::MapT)
                .unwrap()
                .as_map_t()
                .unwrap()
                .dmr()
                .to_string(),
            "2001:db8:5::/64"
        );

        let dslite = data.offer(Capability::DsLite).unwrap().as_dslite().unwrap();
        assert_eq!(
            dslite.aftr(),
            &TunnelEndpoint::Ipv6("2001:db8::1".parse().unwrap())
        );

        let ipip = data.offer(Capability::IpIp).unwrap().as_ipip().unwrap();
        assert_eq!(
            ipip.tunnels()[0].local(),
            "2001:db8::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            ipip.tunnels()[0].remote(),
            "2001:db8::3".parse::<Ipv6Addr>().unwrap()
        );

        let lw4o6 = data.offer(Capability::Lw4o6).unwrap().as_lw4o6().unwrap();
        assert_eq!(lw4o6.lwaftr().to_string(), "lwaftr.example");
        assert_eq!(lw4o6.binding_prefix().to_string(), "2001:db8:3:1200::/56");
        assert_eq!(lw4o6.public_ipv4_address(), Ipv4Addr::new(203, 0, 113, 16));
        assert_eq!(lw4o6.port_set().psid(), 3);
        assert_eq!(lw4o6.port_set().psid_length(), 8);
        assert_eq!(lw4o6.port_set().psid_offset(), 6);

        let map_e = data.offer(Capability::MapE).unwrap().as_map_e().unwrap();
        assert_eq!(map_e.version(), MapEVersion::Draft03);
        assert_eq!(map_e.mode(), MapMode::HubAndSpoke);
        assert_eq!(map_e.br(), "2001:db8::4".parse::<Ipv6Addr>().unwrap());
        assert_eq!(map_e.rules()[0].ipv6().to_string(), "2001:db8:1:ab00::/56");
        assert_eq!(map_e.rules()[0].ipv4().to_string(), "203.0.113.0/24");
        assert_eq!(map_e.rules()[0].ea_length(), 12);
        assert_eq!(map_e.rules()[0].psid_offset(), 4);

        assert!(data.xlat464().is_some());
        assert!(data.dslite().is_some());
        assert!(data.ipip().is_some());
        assert!(data.lw4o6().is_some());
        assert!(data.map_e().is_some());
        assert!(data.map_t().is_some());
    }

    #[test]
    fn parses_the_upstream_full_response_example() {
        let data = ProvisioningData::parse(&format!(
            r#"{{
                "enabler_name":"A VNE",
                "service_name":"Highspeed 4over6",
                "isp_name":"ISP-A",
                "ttl":86400,
                "token":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "auth":"ok",
                "order":["map_e","dslite"],
                "ipv6_mostly":true,
                "map_e":{{"version":0,"mesh":true,"br":"2001:db8:1::1","rules":[{RULE}]}},
                "dslite":{{"aftr":"aftr.example.net"}},
                "lw4o6":{{"lwaftr":"lwaftr.example.net","ipv6":"2001:db8:3:100::/56","ipv4":"203.0.113.16","psid":3,"psid_length":8,"psid_offset":6}},
                "map_t":{{"dmr":"2001:db8:5::/64","rules":[{{"ipv6":"2001:db8:5:100::/56","ipv4":"203.0.113.32/28","ea_length":8,"psid_offset":4}}]}},
                "464xlat":{{"nat64prefix":"2001:db8:6::/96"}},
                "ipip":[{{"ipv6_local":"2001:db8:7::1","ipv6_remote":"2001:db8:7::2","ipv4":"192.0.2.17/30"}}]
            }}"#
        ))
        .unwrap();

        assert_eq!(data.provider_info().enabler_name(), "A VNE");
        assert_eq!(
            data.provider_info().service_name(),
            Some("Highspeed 4over6")
        );
        assert_eq!(data.provider_info().isp_name(), Some("ISP-A"));
        assert_eq!(data.ipv6_mostly(), Some(true));
        assert_eq!(
            data.select(&[Capability::DsLite, Capability::MapE])
                .unwrap()
                .capability(),
            Capability::MapE
        );
        assert!(data.offer(Capability::Xlat464).is_some());
        assert!(data.xlat464().is_some());
    }

    #[test]
    fn accepts_map_modes_and_defaults() {
        for (mesh, expected) in [
            ("", MapMode::HubAndSpoke),
            ("\"mesh\":false,", MapMode::HubAndSpoke),
            ("\"mesh\":0,", MapMode::HubAndSpoke),
            ("\"mesh\":true,", MapMode::Mesh),
            ("\"mesh\":1,", MapMode::Mesh),
        ] {
            let data = ProvisioningData::parse(&format!(r#"{{"enabler_name":"x","order":["map_e"],"map_e":{{{mesh}"br":"2001:db8::1","rules":[{RULE}]}}}}"#)).unwrap();
            assert_eq!(
                data.offer(Capability::MapE)
                    .unwrap()
                    .as_map_e()
                    .unwrap()
                    .mode(),
                expected
            );
        }
    }

    #[test]
    fn accepts_map_e_versions_and_rejects_other_version_or_mode_values() {
        for (version, expected) in [
            (None, MapEVersion::Draft03),
            (Some(0), MapEVersion::Draft03),
            (Some(1), MapEVersion::Rfc7597),
        ] {
            let mut offer = serde_json::json!({
                "br": "2001:db8::1",
                "rules": [valid_rule()]
            });
            if let Some(version) = version {
                offer["version"] = Value::from(version);
            }
            let data = ProvisioningData::parse(&response(Capability::MapE, offer, true)).unwrap();
            assert_eq!(
                data.offer(Capability::MapE)
                    .unwrap()
                    .as_map_e()
                    .unwrap()
                    .version(),
                expected
            );
        }

        for (member, value, path) in [
            ("version", serde_json::json!(2), "map_e.version"),
            ("version", serde_json::json!(null), "map_e.version"),
            ("mesh", serde_json::json!("true"), "map_e.mesh"),
            ("mesh", serde_json::json!(2), "map_e.mesh"),
            ("mesh", serde_json::json!(null), "map_e.mesh"),
        ] {
            let mut offer = serde_json::json!({
                "br": "2001:db8::1",
                "rules": [valid_rule()]
            });
            offer[member] = value;
            assert_error_path(Capability::MapE, offer, path);
        }
    }

    #[test]
    fn validates_nat64_prefix_lengths() {
        for length in [32, 40, 48, 56, 64, 96] {
            let offer = serde_json::json!({"nat64prefix": format!("2001:db8::1/{length}")});
            let data =
                ProvisioningData::parse(&response(Capability::Xlat464, offer, true)).unwrap();
            assert_eq!(
                data.offer(Capability::Xlat464)
                    .unwrap()
                    .as_xlat464()
                    .unwrap()
                    .nat64_prefix()
                    .prefix_len(),
                length
            );
        }
        for length in [0, 31, 33, 65, 95, 97, 128] {
            assert_error_path(
                Capability::Xlat464,
                serde_json::json!({"nat64prefix": format!("2001:db8::/{length}")}),
                "464xlat.nat64prefix",
            );
        }
    }

    #[test]
    fn validates_map_rule_count_boundaries() {
        for (capability, maximum) in [(Capability::MapE, 256), (Capability::MapT, 200)] {
            for count in [1, maximum] {
                let rules = vec![valid_rule(); count];
                let offer = match capability {
                    Capability::MapE => serde_json::json!({"br": "2001:db8::1", "rules": rules}),
                    Capability::MapT => serde_json::json!({"dmr": "2001:db8::/64", "rules": rules}),
                    _ => unreachable!(),
                };
                assert!(ProvisioningData::parse(&response(capability, offer, true)).is_ok());
            }

            for count in [0, maximum + 1] {
                let rules = vec![valid_rule(); count];
                let offer = match capability {
                    Capability::MapE => serde_json::json!({"br": "2001:db8::1", "rules": rules}),
                    Capability::MapT => serde_json::json!({"dmr": "2001:db8::/64", "rules": rules}),
                    _ => unreachable!(),
                };
                assert_error_path(capability, offer, &format!("{}.rules", capability.as_str()));
            }
        }
    }

    #[test]
    fn accepts_prefix_assignment_rules_and_rejects_invalid_map_widths() {
        let prefix_assignment = serde_json::json!({
            "br": "2001:db8::1",
            "rules": [{
                "ipv6": "2001:db8::/40",
                "ipv4": "192.0.2.0/24",
                "ea_length": 4,
                "psid_offset": 15
            }]
        });
        assert!(
            ProvisioningData::parse(&response(Capability::MapE, prefix_assignment, true)).is_ok()
        );

        for (ea_length, psid_offset, path) in [
            (25, 0, "map_e.rules[0].ea_length"),
            (16, 9, "map_e.rules[0].psid_offset"),
        ] {
            let offer = serde_json::json!({
                "br": "2001:db8::1",
                "rules": [{
                    "ipv6": "2001:db8::/40",
                    "ipv4": "192.0.2.0/24",
                    "ea_length": ea_length,
                    "psid_offset": psid_offset
                }]
            });
            assert_error_path(Capability::MapE, offer, path);
        }

        let impossible_ipv6_width = serde_json::json!({
            "br": "2001:db8::1",
            "rules": [{
                "ipv6": "2001:db8::/120",
                "ipv4": "192.0.2.0/24",
                "ea_length": 12,
                "psid_offset": 0
            }]
        });
        assert_error_path(
            Capability::MapE,
            impossible_ipv6_width,
            "map_e.rules[0].ea_length",
        );
    }

    #[test]
    fn exposes_mapping_rule_derivations_and_validates_delegated_prefixes() {
        let data = ProvisioningData::parse(&response(
            Capability::MapE,
            serde_json::json!({"br": "2001:db8::1", "rules": [valid_rule()]}),
            true,
        ))
        .unwrap();
        let rule = &data.map_e().unwrap().rules()[0];
        assert_eq!(rule.ipv4_suffix_length(), 8);
        assert_eq!(rule.psid_length(), 4);
        assert!(rule.uses_address_sharing());
        assert_eq!(
            rule.validate_delegated_prefix("2001:db8:1::/68".parse().unwrap()),
            Ok(())
        );
        assert_eq!(
            rule.validate_delegated_prefix("2001:db8:2::/68".parse().unwrap()),
            Err(MappingRulePrefixError::OutsideRule)
        );
        assert_eq!(
            rule.validate_delegated_prefix("2001:db8:1::/67".parse().unwrap()),
            Err(MappingRulePrefixError::TooShort)
        );

        let prefix_rule = ProvisioningData::parse(&response(
            Capability::MapE,
            serde_json::json!({
                "br": "2001:db8::1",
                "rules": [{
                    "ipv6": "2001:db8::/40",
                    "ipv4": "192.0.2.0/24",
                    "ea_length": 4,
                    "psid_offset": 15
                }]
            }),
            true,
        ))
        .unwrap();
        let rule = &prefix_rule.map_e().unwrap().rules()[0];
        assert_eq!(rule.ipv4_suffix_length(), 4);
        assert_eq!(rule.psid_length(), 0);
        assert!(!rule.uses_address_sharing());
    }

    #[test]
    fn rejects_missing_null_wrong_type_and_wrong_address_family_with_precise_paths() {
        let cases = [
            (Capability::DsLite, serde_json::json!(null), "dslite"),
            (Capability::DsLite, serde_json::json!({}), "dslite.aftr"),
            (
                Capability::DsLite,
                serde_json::json!({"aftr": null}),
                "dslite.aftr",
            ),
            (
                Capability::DsLite,
                serde_json::json!({"aftr": 1}),
                "dslite.aftr",
            ),
            (
                Capability::DsLite,
                serde_json::json!({"aftr": "192.0.2.1"}),
                "dslite.aftr",
            ),
            (
                Capability::DsLite,
                serde_json::json!({"aftr": "bad..name"}),
                "dslite.aftr",
            ),
            (
                Capability::Xlat464,
                serde_json::json!({"nat64prefix": "192.0.2.0/24"}),
                "464xlat.nat64prefix",
            ),
            (
                Capability::Xlat464,
                serde_json::json!({"nat64prefix": "2001:db8::/+96"}),
                "464xlat.nat64prefix",
            ),
            (
                Capability::IpIp,
                serde_json::json!([{"ipv6_local":"192.0.2.1","ipv6_remote":"2001:db8::1","ipv4":"192.0.2.1/24"}]),
                "ipip[0].ipv6_local",
            ),
            (
                Capability::IpIp,
                serde_json::json!([{"ipv6_local":"2001:db8::1","ipv6_remote":"2001:db8::2","ipv4":"2001:db8::1/64"}]),
                "ipip[0].ipv4",
            ),
            (
                Capability::Lw4o6,
                serde_json::json!({"lwaftr":"lw.example","ipv6":"2001:db8::/56","ipv4":"2001:db8::1","psid":0,"psid_length":0,"psid_offset":0}),
                "lw4o6.ipv4",
            ),
            (
                Capability::MapE,
                serde_json::json!({"br":"192.0.2.1","rules":[valid_rule()]}),
                "map_e.br",
            ),
            (
                Capability::MapT,
                serde_json::json!({"dmr":"2001:db8::/97","rules":[valid_rule()]}),
                "map_t.dmr",
            ),
            (
                Capability::MapT,
                serde_json::json!({"dmr":"2001:db8::/64","rules":[{"ipv6":"2001:db8::/40","ipv4":"192.0.2.0/24","ea_length":49,"psid_offset":0}]}),
                "map_t.rules[0].ea_length",
            ),
            (
                Capability::MapT,
                serde_json::json!({"dmr":"2001:db8::/64","rules":[{"ipv6":"2001:db8::/40","ipv4":"192.0.2.0/24","ea_length":8,"psid_offset":16}]}),
                "map_t.rules[0].psid_offset",
            ),
        ];
        for (capability, offer, path) in cases {
            assert_error_path(capability, offer, path);
        }
    }

    #[test]
    fn validates_lw4o6_port_sets() {
        let make_offer = |psid, length, offset| {
            serde_json::json!({
                "lwaftr": "lw.example",
                "ipv6": "2001:db8::/56",
                "ipv4": "192.0.2.1",
                "psid": psid,
                "psid_length": length,
                "psid_offset": offset
            })
        };
        for (psid, length, offset) in [(0, 0, 15), (u16::MAX, 16, 0), (1, 1, 15)] {
            assert!(
                ProvisioningData::parse(&response(
                    Capability::Lw4o6,
                    make_offer(psid, length, offset),
                    true,
                ))
                .is_ok()
            );
        }
        for (psid, length, offset, path) in [
            (1, 0, 0, "lw4o6.psid"),
            (4, 2, 0, "lw4o6.psid"),
            (0, 2, 15, "lw4o6.psid_length"),
            (0, 0, 16, "lw4o6.psid_offset"),
            (0, 17, 0, "lw4o6.psid_length"),
        ] {
            assert_error_path(Capability::Lw4o6, make_offer(psid, length, offset), path);
        }
    }

    #[test]
    fn accepts_empty_ipip_tunnel_array() {
        let data =
            ProvisioningData::parse(&response(Capability::IpIp, Value::Array(Vec::new()), true))
                .unwrap();
        assert!(
            data.offer(Capability::IpIp)
                .unwrap()
                .as_ipip()
                .unwrap()
                .tunnels()
                .is_empty()
        );
    }

    #[test]
    fn rejects_unselected_invalid_offer_and_requires_xlat_for_ipv6_mostly() {
        let invalid = ProvisioningData::parse(
            r#"{"enabler_name":"x","order":[],"dslite":{"aftr":"192.0.2.1"}}"#,
        )
        .unwrap_err();
        assert!(matches!(
            invalid,
            crate::ProvisioningDataError::Offer {
                capability: Capability::DsLite,
                ..
            }
        ));
        let missing =
            ProvisioningData::parse(r#"{"enabler_name":"x","order":[],"ipv6_mostly":true}"#)
                .unwrap_err();
        assert!(matches!(
            missing,
            crate::ProvisioningDataError::MissingIpv6MostlyOffer
        ));
    }

    #[test]
    fn preserves_unknown_offer_members_in_raw_json() {
        let data = ProvisioningData::parse(r#"{"enabler_name":"x","order":["dslite"],"dslite":{"aftr":"a.example","future":{"value":true}}}"#).unwrap();
        assert_eq!(
            data.raw_offer(Capability::DsLite).unwrap()["future"]["value"],
            true
        );
    }

    #[test]
    fn canonicalizes_dns_names_without_changing_raw_offers() {
        let data = ProvisioningData::parse(
            r#"{"enabler_name":"x","order":["dslite"],"dslite":{"aftr":"AFTR.Example."}}"#,
        )
        .unwrap();

        assert_eq!(data.dslite().unwrap().aftr().to_string(), "aftr.example.");
        assert_eq!(
            data.raw_offer(Capability::DsLite).unwrap()["aftr"],
            "AFTR.Example."
        );
    }
}
