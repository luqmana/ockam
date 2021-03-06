// ---
// #![no_std] if the standard library is not present.

#![cfg_attr(not(feature = "std"), no_std)]

// ---
// Export the #[node] attribute macro.

pub use ockam_node_attribute::*;

// ---
// Export node implementation

#[cfg(all(feature = "std", feature = "ockam_node"))]
pub use ockam_node::*;

#[cfg(all(not(feature = "std"), feature = "ockam_node_no_std"))]
pub use ockam_node_no_std::*;

// ---

mod profile;
pub use profile::*;
mod contacts;
pub use contacts::*;
mod error;
pub use error::*;
mod credential;
mod lease;

pub use credential::*;
pub use lease::*;

pub use ockam_core::{Address, Encoded, Error, Message, Result, Worker};
