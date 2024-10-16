use super::Error;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD, BASE64_URL_SAFE};
use schemars::schema::{Schema, SchemaObject, StringValidation};
use chrono::{Utc, DateTime as ChronoDateTime};
use chrono::format::SecondsFormat;
use schemars::JsonSchema;
use serde::{Serialize, Deserialize};

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct DateTime {
    pub inner: ChronoDateTime<Utc>
}

impl DateTime {
    pub fn from_timestamp(timestamp: u64) -> Result<DateTime, Error> {
        Ok(DateTime{inner:
            ChronoDateTime::<Utc>::from_timestamp(timestamp as i64, 0)
            .ok_or(Error::bad_request("DateTime::from_timestamp", "Could not create date from timestamp"))?
        })
    }
    pub fn now() -> DateTime {
        DateTime{inner: Utc::now()}
    }
    pub fn timestamp(&self) -> u64 {
        Some(self.inner.timestamp()).filter(|t| *t >= 0).expect("timestamp was negative") as u64
    }
}

impl std::fmt::Display for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.to_rfc3339_opts(SecondsFormat::Micros, true))
    }
}

impl std::str::FromStr for DateTime {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DateTime{inner: ChronoDateTime::parse_from_rfc3339(s)?.to_utc()})
    }
}

pub struct Schemas {}
impl Schemas {
    pub fn regex(regex: String) -> Schema {
        Schema::Object(SchemaObject{
            string: Some(Box::new(StringValidation {
                max_length: None,
                min_length: None,
                pattern: Some(regex)
            })),
            ..Default::default()
        })
    }
    pub fn any() -> Schema {
        Schema::Bool(true)
    }
}

pub enum Convert {
    ZBase32,
    Base64Url,
    Base64UrlUnpadded
}

impl Convert {
    pub fn encode(&self, data: &[u8]) -> String {
        match &self {
            Convert::ZBase32 => zbase32::encode(data),
            Convert::Base64Url => BASE64_URL_SAFE.encode(data),
            Convert::Base64UrlUnpadded => BASE64_URL_SAFE_NO_PAD.encode(data)
        }
    }

    pub fn decode(&self, input: &str) -> Result<Vec<u8>, Error> {
        Ok(match &self {
            Convert::ZBase32 => zbase32::decode(input)?,
            Convert::Base64Url => BASE64_URL_SAFE.decode(input)?,
            Convert::Base64UrlUnpadded => BASE64_URL_SAFE_NO_PAD.decode(input)?
        })
    }
}

