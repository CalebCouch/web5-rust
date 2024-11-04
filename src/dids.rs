use super::error::Error;
mod traits;
pub use traits::{DidResolver, DidDocument};
mod structs;
pub use structs::{
    DefaultDidResolver,
    DidService,
    DidKeyPair,
    DidKeyUri,
    DidMethod,
    Endpoint,
    Identity,
    DidType,
    DidUri,
    Did
};
pub mod signing;

mod dht_document;
pub use dht_document::{DhtDocument};

mod pkarr;
mod dns_packet;
