//! This crate provides the common abstractions used across transports for Ockam's Routing Protocol.
//!
//! The Routing Protocol decouples Ockam's suite of cryptographic protocols,
//! like secure channels, key lifecycle, credential exchange, enrollment etc. from
//! the underlying transport protocols. This allows applications to establish
//! end-to-end trust between entities, independently from the underlying transport.

pub mod error;
pub mod traits;

pub use error::*;
pub use traits::*;
