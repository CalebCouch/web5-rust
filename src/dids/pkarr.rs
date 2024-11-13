use super::Error;

use crate::ed25519::{SecretKey};

use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_bencode::value::Value;

use url::Url;

const PKARR_SIZE_LIMIT: usize = 1000;

#[derive(Deserialize, Serialize)]
struct Data {
    seq: u64,
    v: Value
}

pub struct PkarrRelay {}

impl PkarrRelay {
    pub async fn put(url: Url, dns_packet: Vec<u8>, secret_key: &SecretKey) -> Result<(), Error> {
        let seq = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut map: HashMap<Vec<u8>, Value> = HashMap::new();
        map.insert(b"seq".to_vec(), Value::Int(seq.try_into().unwrap()));
        map.insert(b"v".to_vec(), Value::Bytes(dns_packet.clone()));

        let v = serde_bencode::to_bytes(&Value::Dict(map))?;
        let v = v[1..v.len()-1].to_vec();
        if v.len() > PKARR_SIZE_LIMIT {return Err(Error::bad_request("Document length exceeds limit"));}

        let sig = secret_key.sign(&v).to_vec();
        let body = [sig, seq.to_be_bytes().to_vec(), dns_packet].concat();

        let res = reqwest::Client::new().put(url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send().await?;

        if !res.status().is_success() {
            Err(Error::bad_response(&res.text().await?))
        } else {
            Ok(())
        }
    }

    pub async fn get(url: Url) -> Result<Option<Vec<u8>>, Error> {
        let res = reqwest::get(url).await?;
        if !res.status().is_success() {
            if res.status() == reqwest::StatusCode::NOT_FOUND {return Ok(None);}
            Err(Error::bad_response(&res.text().await?))
        } else {
            Ok(Some(res.bytes().await?.to_vec()))
        }
    }
}
