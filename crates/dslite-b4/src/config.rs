use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU8, NonZeroU64};
use std::path::PathBuf;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::tunnel::EncapsulationLimit;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub tunnel: TunnelConfig,
    pub aftr: AftrConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
    pub health: HealthConfig,
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: LogLevel,
}

#[derive(Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(
        default = "default_tunnel_name",
        deserialize_with = "deserialize_tunnel_name"
    )]
    pub name: String,
    pub local_v6: Option<Ipv6Addr>,
    #[serde(
        default = "default_tunnel_local_v4",
        deserialize_with = "deserialize_b4_v4"
    )]
    pub local_v4: Ipv4Addr,
    pub mtu: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_encapsulation_limit")]
    pub encapsulation_limit: Option<EncapsulationLimit>,
}

fn deserialize_b4_v4<'de, D>(d: D) -> Result<Ipv4Addr, D::Error>
where
    D: Deserializer<'de>,
{
    let addr = Ipv4Addr::deserialize(d)?;
    let o = addr.octets();
    // RFC 6333 5.7: reserved subnet 192.0.0.0/29
    // - .0 (subnet address)
    // - .1 (AFTR element)
    // - .7 (broadcast)
    if o[..3] != [192, 0, 0] || !(2..=6).contains(&o[3]) {
        return Err(serde::de::Error::custom(
            "according to RFC 6333 tunnel.local_v4 must be in the host range 192.0.0.2 through 192.0.0.6",
        ));
    }
    Ok(addr)
}

fn deserialize_tunnel_name<'de, D>(d: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let name = String::deserialize(d)?;

    validate_tunnel_name(&name).map_err(serde::de::Error::custom)?;

    Ok(name)
}

#[cfg(target_os = "linux")]
fn validate_tunnel_name(name: &str) -> Result<(), &'static str> {
    if !(1..=15).contains(&name.len()) {
        return Err("must contain from 1 through 15 bytes");
    }

    if matches!(name, "." | "..") {
        return Err("cannot be '.' or '..'");
    }

    if name
        .bytes()
        .any(|byte| matches!(byte, b'\0' | b'/' | b':' | b'%') || byte.is_ascii_whitespace())
    {
        return Err("cannot contain NUL, '/', ':', '%', or whitespace");
    }

    Ok(())
}

#[cfg(target_os = "illumos")]
fn validate_tunnel_name(name: &str) -> Result<(), &'static str> {
    if !(1..=31).contains(&name.len()) {
        return Err("must contain from 1 through 31 bytes");
    }

    let bytes = name.as_bytes();

    if bytes[0].is_ascii_digit() {
        return Err("cannot start with a digit");
    }

    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
    {
        return Err("can contain only letters, digits, '_', and '.'");
    }

    let suffix_len = bytes
        .iter()
        .rev()
        .take_while(|byte| byte.is_ascii_digit())
        .count();

    if suffix_len == 0 {
        return Err("must end with a numeric suffix");
    }

    let suffix_start = bytes.len() - suffix_len;
    if suffix_len > 1 && bytes[suffix_start] == b'0' {
        return Err("numeric suffix cannot have a leading zero");
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EncapsulationLimitRepr {
    Value(NonZeroU8),
    Keyword(String),
}

fn deserialize_encapsulation_limit<'de, D>(d: D) -> Result<Option<EncapsulationLimit>, D::Error>
where
    D: Deserializer<'de>,
{
    match EncapsulationLimitRepr::deserialize(d)? {
        EncapsulationLimitRepr::Value(n) => Ok(Some(EncapsulationLimit::Value(n))),
        EncapsulationLimitRepr::Keyword(s) if s == "disabled" => {
            Ok(Some(EncapsulationLimit::Disabled))
        }
        EncapsulationLimitRepr::Keyword(_) => Err(serde::de::Error::custom(
            "encapsulation_limit must be an integer from 1 through 255 or 'disabled'",
        )),
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(from = "String")]
pub enum AftrAddress {
    Ip(Ipv6Addr),
    Fqdn(String),
}

impl From<String> for AftrAddress {
    fn from(value: String) -> Self {
        if let Ok(addr) = value.parse::<Ipv6Addr>() {
            Self::Ip(addr)
        } else {
            Self::Fqdn(value)
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct AftrConfig {
    pub address: Option<AftrAddress>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMethod {
    #[default]
    None,
    Hb46pp,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryConfig {
    #[serde(default)]
    pub method: DiscoveryMethod,
    #[serde(default = "default_discovery_vendorid")]
    pub vendor_id: String,
    #[serde(default = "default_discovery_product")]
    pub product: String,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            method: DiscoveryMethod::None,
            vendor_id: default_discovery_vendorid(),
            product: default_discovery_product(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default = "default_health_interval")]
    pub interval_secs: NonZeroU64,
    #[serde(default = "default_aftr_missing_grace_secs")]
    pub aftr_missing_grace_secs: u64,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "default_runtime_state_dir")]
    pub state_dir: PathBuf,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            state_dir: default_runtime_state_dir(),
        }
    }
}

/// Configuration diagnostic safe for supervisor logs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigParseError {
    #[error("invalid configuration at line {line}, column {column}")]
    Located { line: usize, column: usize },
    #[error("invalid configuration")]
    Unlocated,
}

/// Parses configuration without including source lines or values in errors.
pub fn parse(text: &str) -> Result<Config, ConfigParseError> {
    toml::from_str(text).map_err(|error| match error.span() {
        Some(span) => {
            let (line, column) = line_column(text, span.start);
            ConfigParseError::Located { line, column }
        }
        None => ConfigParseError::Unlocated,
    })
}

/// Parses configuration with the original TOML diagnostic, which may contain
/// source lines and values.
pub fn parse_with_source(text: &str) -> Result<Config, toml::de::Error> {
    toml::from_str(text)
}

fn line_column(text: &str, byte_offset: usize) -> (usize, usize) {
    let prefix = &text.as_bytes()[..byte_offset.min(text.len())];
    let line = prefix.iter().filter(|&&byte| byte == b'\n').count() + 1;
    let column = prefix
        .iter()
        .rev()
        .take_while(|&&byte| byte != b'\n')
        .count()
        + 1;
    (line, column)
}

fn default_tunnel_name() -> String {
    "dslite0".into()
}

fn default_health_interval() -> NonZeroU64 {
    NonZeroU64::new(30).unwrap()
}

fn default_tunnel_local_v4() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 0, 2)
}

fn default_runtime_state_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    return PathBuf::from("/run/dslite-b4");
    #[cfg(target_os = "illumos")]
    PathBuf::from("/var/run/dslite-b4")
}

fn default_aftr_missing_grace_secs() -> u64 {
    600
}

fn default_discovery_vendorid() -> String {
    "000000".into()
}

fn default_discovery_product() -> String {
    "dslite-b4".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logging_levels_and_defaults_to_info() {
        let default: LoggingConfig = toml::from_str("").unwrap();
        assert_eq!(default.level, LogLevel::Info);

        for (name, expected) in [
            ("error", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("debug", LogLevel::Debug),
            ("trace", LogLevel::Trace),
        ] {
            let config: LoggingConfig = toml::from_str(&format!(r#"level = "{name}""#)).unwrap();
            assert_eq!(config.level, expected);
        }

        assert!(toml::from_str::<LoggingConfig>(r#"level = "verbose""#).is_err());
    }

    #[test]
    fn parses_encapsulation_limit() {
        let cases = [
            ("", None),
            (
                r#"encapsulation_limit = "disabled""#,
                Some(EncapsulationLimit::Disabled),
            ),
            (
                "encapsulation_limit = 4",
                Some(EncapsulationLimit::Value(NonZeroU8::new(4).unwrap())),
            ),
        ];

        for (input, expected) in cases {
            let config: TunnelConfig = toml::from_str(input).unwrap();

            assert_eq!(config.encapsulation_limit, expected);
        }
    }

    #[test]
    fn rejects_invalid_encapsulation_limit() {
        let cases = [
            "encapsulation_limit = 0",
            "encapsulation_limit = 256",
            r#"encapsulation_limit = "automatic""#,
        ];

        for input in cases {
            assert!(toml::from_str::<TunnelConfig>(input).is_err());
        }
    }

    #[test]
    fn parses_b4_v4_host_addresses() {
        for last_octet in 2..=6 {
            let input = format!(r#"local_v4 = "192.0.0.{last_octet}""#);
            let config: TunnelConfig = toml::from_str(&input).unwrap();

            assert_eq!(config.local_v4, Ipv4Addr::new(192, 0, 0, last_octet));
        }
    }

    #[test]
    fn rejects_non_b4_v4_host_addresses() {
        let cases = [
            r#"local_v4 = "192.0.0.0""#,
            r#"local_v4 = "192.0.0.1""#,
            r#"local_v4 = "192.0.0.7""#,
            r#"local_v4 = "192.0.1.2""#,
            r#"local_v4 = "198.51.100.2""#,
        ];

        for input in cases {
            assert!(toml::from_str::<TunnelConfig>(input).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_valid_linux_tunnel_names() {
        let cases = [
            "dslite0",
            "dslite-evt",
            "0dslite",
            "dslite_0",
            "abcdefghijklmn0",
        ];

        for name in cases {
            let input = format!(r#"name = "{name}""#);
            let config: TunnelConfig = toml::from_str(&input).unwrap();

            assert_eq!(config.name, name);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_invalid_linux_tunnel_names() {
        let cases = [
            "",
            ".",
            "..",
            "abcdefghijklmnop",
            "dslite/0",
            "dslite:0",
            "dslite 0",
            "dslite%d",
        ];

        for name in cases {
            let input = format!(r#"name = "{name}""#);

            assert!(
                toml::from_str::<TunnelConfig>(&input).is_err(),
                "invalid name accepted: {name:?}"
            );
        }
    }

    #[cfg(target_os = "illumos")]
    #[test]
    fn validates_illumos_tunnel_names() {
        let cases = [
            ("dslite0".to_string(), true),
            ("dslite10".to_string(), true),
            ("dslite_0".to_string(), true),
            ("dslite.0".to_string(), true),
            (format!("{}0", "a".repeat(30)), true),
            ("".to_string(), false),
            ("0dslite0".to_string(), false),
            ("dslite".to_string(), false),
            ("dslite01".to_string(), false),
            ("dslite-0".to_string(), false),
            (format!("{}0", "a".repeat(31)), false),
        ];

        for (name, expected_valid) in cases {
            let input = format!(r#"name = "{name}""#);
            let valid = toml::from_str::<TunnelConfig>(&input).is_ok();

            assert_eq!(valid, expected_valid, "name: {name:?}");
        }
    }
}
