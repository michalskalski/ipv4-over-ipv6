/// Client-facing transport abstractions for HB46PP provisioning.
#[cfg(feature = "client")]
pub mod client;
mod model;

pub use model::*;
