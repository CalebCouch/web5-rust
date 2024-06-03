use super::error::Error;

use crate::common::{Convert};
use crate::crypto::ed25519;
use crate::crypto::ed25519::Ed25519;
use crate::crypto::traits::CryptoAlgorithm;


use url::Url;
use http::request::Request;
use serde::{Deserialize, Serialize};

use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use serde_bencode::value::Value;

#[derive(Deserialize, Serialize)]
struct Data {
    seq: u64,
    v: Value
}

pub struct PkarrRelay {}

impl PkarrRelay {
    pub async fn put(url: Url, dns_packet: Vec<u8>, secret_key: ed25519::SecretKey) -> Result<(), Error> {
        let seq = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut map: HashMap<Vec<u8>, Value> = HashMap::new();
        map.insert(b"seq".to_vec(), Value::Int(seq.try_into().unwrap()));
        map.insert(b"v".to_vec(), Value::Bytes(dns_packet.clone()));

        let v = serde_bencode::to_bytes(&Value::Dict(map))?;
        let v = v[1..v.len()-1].to_vec();//TODO: WHAT is this?
        if v.len() > 1000 { return Err(Error::InvalidDidDocumentLength(v.len().to_string())); }

        let sig = Ed25519::sign(&secret_key, &v).to_vec();
        let body = [sig, seq.to_be_bytes().to_vec(), dns_packet].concat();

        let res = reqwest::Client::new().put(url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        if !res.status().is_success() {
            Err(Error::PkarrResponse(res.text().await?))
        } else {
            Ok(())
        }
    }

    pub async fn get(url: Url, public_key: ed25519::PublicKey) -> Result<Vec<u8>, Error> {
        let res = reqwest::Client::new().get(url).send().await?;
        if !res.status().is_success() {
            Err(Error::PkarrResponse(res.text().await?))
        } else {
            Ok(res.bytes().await?.to_vec())
        }
    }
}
