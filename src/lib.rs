mod error;
pub use error::Error;

mod common;
mod ed25519;
pub mod dids;

#[cfg(not(feature = "dwn"))]
mod dwn;

#[cfg(feature = "dwn")]
pub mod dwn;

#[cfg(feature = "agent")]
pub mod agent;

pub extern crate simple_database;

#[cfg(test)]
mod tests;

