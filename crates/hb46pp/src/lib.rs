#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

/// Client and transport abstractions for HB46PP provisioning.
#[cfg(feature = "client")]
pub mod client;
mod model;

pub use model::*;
