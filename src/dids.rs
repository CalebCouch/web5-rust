#![allow(dead_code)]
pub mod error;
pub use error::Error;

pub mod did_core;
pub mod did_method;
pub mod did_resolver;
pub use did_resolver::DidResolver;
pub mod did_dht;
pub use did_dht::{DidDht};
pub mod dns_packet;
pub mod pkarr;
