use super::Error;

use schemars::schema::{Schema, SchemaObject, StringValidation};
use chrono::{Utc, DateTime as ChronoDateTime};
use chrono::format::SecondsFormat;
use url::Url as _Url;
pub use uuid::Uuid as _Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Uuid {
    inner: _Uuid
}

impl Uuid {
    pub fn new() -> Self {
        Uuid{inner: _Uuid::new_v4()}
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.inner.as_bytes()))
    }
}

impl std::str::FromStr for Uuid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Uuid{inner: _Uuid::from_bytes(hex::decode(s)?.try_into().or(Err(Error::parse("Uuid", s)))?)})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Url {
    url: _Url
}

impl Url {
    pub fn path(&self) -> &str {self.url.path()}
    pub fn get(&self) -> _Url {self.url.clone()}
    pub fn path_segments(&self) -> Option<core::str::Split<'_, char>> {
        self.url.path_segments()
    }

    pub fn join(&self, s: &str) -> Result<Url, Error> {
        Ok(Url{url: self.url.join(s)?})
    }
    pub fn add_path(&self, s: &str) -> Result<Url, Error> {
        Ok(Url{url: self.url.join(&format!("{}{}", self.url.path(), s))?})
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl std::str::FromStr for Url {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Url{url: _Url::parse(s).or(Err(Error::Parse("Url".to_string(), s.to_string())))?})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct DateTime {
    date: ChronoDateTime<Utc>
}

impl DateTime {
    pub fn new(date: ChronoDateTime<Utc>) -> DateTime {
        DateTime{date}
    }
    pub fn now() -> DateTime {
        DateTime{date: Utc::now()}
    }
    pub fn timestamp(&self) -> u64 {
        Some(self.date.timestamp()).filter(|t| *t >= 0).expect("timestamp was negative") as u64
    }
}

impl std::fmt::Display for DateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.date.to_rfc3339_opts(SecondsFormat::Micros, true))
    }
}

impl std::str::FromStr for DateTime {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DateTime{date: ChronoDateTime::parse_from_rfc3339(s)?.to_utc()})
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

#[derive(schemars::JsonSchema, serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Either<L: Clone, R: Clone> {
    Left(L),
    Right(R)
}

impl<L: Clone, R: Clone> Either<L, R> {
    pub fn left(self) -> Option<L> {if let Either::Left(l) = self {Some(l)} else {None}}
    pub fn right(self) -> Option<R> {if let Either::Right(r) = self {Some(r)} else {None}}
    pub fn is_left(&self) -> bool {matches!(self, Either::Left(_))}
    pub fn is_right(&self) -> bool {!self.is_left()}
    pub fn map_to_right<F>(self, map: F) -> R where F: FnOnce(L) -> R {
        match self {
            Either::Left(l) => map(l),
            Either::Right(r) => r
        }
    }
    pub fn map_to_left<F>(self, map: F) -> L where F: FnOnce(R) -> L {
        match self {
            Either::Left(l) => l,
            Either::Right(r) => map(r)
        }
    }
    pub fn right_or(self, or: Either<L, R>) -> Either<L, R> {
        match self {
            Either::Left(_) => or,
            Either::Right(r) => Either::Right(r)
        }
    }
//  pub fn right_or_else<F>(&self, map: F) -> Either<L, R> where F: FnOnce(&L) -> Either<L, R> {
//      match self {
//          Either::Left(l) => map(l)
//          Either::Right(r) => Either::Right(r)
//      }
//  }
    pub fn map_ref_to_right<F>(&self, map: F) -> R where F: FnOnce(&L) -> R {
        match &self {
            Either::Left(ref l) => map(l),
            Either::Right(ref r) => r.clone()
        }
    }
    pub fn map_ref_to_left<F>(&self, map: F) -> L where F: FnOnce(&R) -> L {
        match &self {
            Either::Left(ref l) => l.clone(),
            Either::Right(ref r) => map(r)
        }
    }
    pub const fn as_ref(&self) -> Either<&L, &R> {
        match *self {
            Either::Left(ref l) => Either::Left(l),
            Either::Right(ref r) => Either::Right(r),
        }
    }
}

impl<L: std::fmt::Display + Clone, R: std::fmt::Display + Clone> std::fmt::Display for Either<L, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}",
            match &self {
                Either::Left(l) => l.to_string(),
                Either::Right(r) => r.to_string(),
            }
        )
    }
}
