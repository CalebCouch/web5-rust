pub mod common;
pub mod ed25519;
pub mod dids;
pub mod dwn;

pub mod error;
pub use error::Error;

#[cfg(test)]
mod tests;

