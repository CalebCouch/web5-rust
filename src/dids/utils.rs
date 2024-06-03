use super::error::Error;

use crate::common::multicodec::{Multicodec, MulticodecCode};

use super::did_core::DidService;

pub struct DwnDidService {
    did_service: DidService,
    enc: Option<Vec<String>>,
    sig: Vec<String>
}

pub fn extract_did_fragment(input: String) -> Option<String> {
    if input.contains('#') {
        if let Some(string) = input.split('#').collect::<Vec<&str>>().pop() {
            return Some(string.to_string());
        }
    }
    None
}

//MOVED lots of DidDocument related methods to did_core::DidDocument

//TODO multibase_id as its own type(its just a prefixed_key from the default multicodec with 'z' prepended
pub fn key_bytes_to_multibase_id(key_bytes: Vec<u8>, multicodec_code: Option<MulticodecCode>, multicodec_name: Option<String>) -> Result<String, Error> {
    let prefixed_key = Multicodec::new().add_prefix(key_bytes, multicodec_code, multicodec_name)?;
    Ok(format!("z{}", bs58::encode(prefixed_key).into_string()))
}

pub fn multibase_id_to_key_bytes(multibase_key_id: String) -> Result<(Vec<u8>, MulticodecCode, String), Error> {
    let prefixed_key = bs58::decode(multibase_key_id[1..].to_string()).into_vec()?;
    Ok(Multicodec::new().remove_prefix(prefixed_key)?)
}
