use super::error::Error;

pub mod permission;
pub mod protocol;
pub mod structs;
pub mod traits;

pub mod private_client;
pub use private_client::PrivateClient;
pub mod public_client;
pub use public_client::PublicClient;
pub mod dm_client;
pub use dm_client::DMClient;
//  pub mod private_agent;
//  pub use private_agent::PrivateAgent;

pub mod server;
pub use server::Server;
pub mod agent;
pub use agent::Agent;
pub mod wallet;
pub use wallet::Wallet;

pub mod json_rpc;
