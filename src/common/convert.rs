use super::error::Error;
use base64ct::{Base64UrlUnpadded, Base64Url, Encoding};
use zbase32;

pub enum Convert {
    ZBase32,
    Base64Url,
    Base64UrlUnpadded
}

//TODO: A better way to size buffer than input.len()*2
impl Convert {
    pub fn encode(&self, data: &[u8]) -> Result<String, Error> {
        Ok(match &self {
            Convert::ZBase32 => zbase32::encode(data),
            Convert::Base64Url => {
                Base64Url::encode(data, &mut vec![0u8; data.len()*2])?.to_string()
            },
            Convert::Base64UrlUnpadded => {
                Base64UrlUnpadded::encode(data, &mut vec![0u8; data.len()*2])?.to_string()
            }
        })
    }

    pub fn decode(&self, input: String) -> Result<Vec<u8>, Error> {
        Ok(match &self {
            Convert::ZBase32 => zbase32::decode(&input)?,
            Convert::Base64Url => {
                Base64Url::decode(input.clone(), &mut vec![0u8; input.len()*2])?.to_vec()
            }
            Convert::Base64UrlUnpadded => {
                Base64UrlUnpadded::decode(input.clone(), &mut vec![0u8; input.len()*2])?.to_vec()
            }
        })
    }
}

