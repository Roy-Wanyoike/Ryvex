//! ryvex-agent library: config, backoff, spec building and the
//! control-plane client. Exposed as a library so the integration
//! suite can drive the same code the binary runs.

pub mod backoff;
pub mod client;
pub mod config;
pub mod spec;
