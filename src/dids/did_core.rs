use super::error::Error;

use regex::Regex;
use std::collections::HashMap;
use serde::{Deserialize, Serialize, Serializer, de};
use crate::crypto::traits;

pub use url::Url;

fn method_pattern() -> String {"([a-z0-9]+)".to_string()}
fn pct_encoded_pattern() -> String {"(?:%[0-9a-fA-F]{2})".to_string()}
fn id_char_pattern() -> String {format!("(?:[a-zA-Z0-9._-]|{})", pct_encoded_pattern())}
fn method_id_pattern() -> String {format!("((?:{}*:)*({}+))", id_char_pattern(), id_char_pattern())}
fn path_pattern() -> String {"(/[^#?]*)?".to_string()}
fn query_pattern() -> String {"([?][^#]*)?".to_string()}
fn fragment_pattern() -> String {"(#.*)?".to_string()}
fn path_query_frag() -> String { format!("(?<path>{})(?<query>{})(?<fragment>{})", path_pattern(), query_pattern(), fragment_pattern()) }
fn did_pattern() -> String {format!("did:(?<method>{}):(?<id>{})", method_pattern(), method_id_pattern())}
fn did_uri_pattern() -> String {format!("^{}{}$", did_pattern(), path_query_frag())}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Method {
    DHT
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DHT => write!(f, "dht")
        }
    }
}

impl Method {
    pub fn parse(did_method: &str) -> Result<Method, Error> {
        Ok(match did_method {
            "dht" => Method::DHT,
            _ => return Err(Error::Parse("did method".to_string(), did_method.to_string()))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Did {
    pub id: String,
    pub method: Method
}

impl Did {
    pub fn new(id: String, method: Method) -> Self {
        Did{id, method}
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}

impl Did {
    pub fn parse(did: &str) -> Result<Did, Error> {
        let error = || Error::Parse("did".to_string(), did.to_string());
        let captures = Regex::new(&did_pattern())?.captures(did).ok_or(error())?;
        let method = Method::parse(captures.name("method").ok_or(error())?.as_str())?;
        let id = captures.name("id").ok_or(error())?.as_str().to_owned();
        Ok(Did{id, method})
    }
    pub fn to_uri(
        &self,
        path: Option<String>,
        query: Option<String>,
        fragment: Option<String>,
        params: Option<HashMap<String, String>>
    ) -> DidUri {
        DidUri{
            id: self.id.clone(),
            method: self.method.clone(),
            path,
            query,
            fragment,
            params
        }
    }
}

//  impl Serialize for Did {
//      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//      where
//          S: Serializer,
//      {
//          println!("bytes: {:?}", self.to_string().as_bytes());
//          serializer.serialize_bytes(self.to_string().as_bytes())
//      }
//  }

//  impl<'de> de::Deserialize<'de> for Did {
//      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//      where
//          D: de::Deserializer<'de>,
//      {
//          struct DidVisitor;

//          impl<'de> de::Visitor<'de> for DidVisitor {
//              type Value = Did;

//              fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
//                  formatter.write_str("Did")
//              }

//              fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
//                  let string = std::str::from_utf8(bytes).or(Err(de::Error::custom::<String>("Invalid Did Bytes".to_string())))?;
//                  Ok(Self::Value::parse(string).or(Err(de::Error::custom::<String>("Invalid Did Bytes".to_string())))?)
//              }
//          }

//          deserializer.deserialize_bytes(DidVisitor {})
//      }
//  }

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct DidUri {
    pub id: String,
    pub method: Method,
    pub path: Option<String>,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub params: Option<HashMap<String, String>>
}

impl DidUri {
    pub fn new(
        id: String,
        method: Method,
        path: Option<String>,
        query: Option<String>,
        fragment: Option<String>,
        params: Option<HashMap<String, String>>
    ) -> DidUri {
        DidUri{id, method, path, query, fragment, params}
    }

    pub fn parse(did_uri: &str) -> Result<DidUri, Error> {
        let error = || Error::Parse(did_uri.to_string(), "did_uri".to_string());
        let captures = Regex::new(&did_uri_pattern())?.captures(&did_uri).ok_or(error())?;
        let method = Method::parse(captures.name("method").filter(|s| !s.as_str().is_empty()).ok_or(error())?.as_str())?;
        let id: String = captures.name("id").filter(|s| !s.as_str().is_empty()).ok_or(error())?.as_str().to_owned();
        let path: Option<String> = captures.name("path").filter(|s| !s.as_str().is_empty()).map(|p| p.as_str().to_owned());
        let (query, params): (Option<String>, Option<HashMap<String, String>>) = match captures.name("query").filter(|s| !s.as_str().is_empty()) {
            None => (None, None),
            Some(q) => {
                println!("{:?}", q);
                let query = q.as_str().to_owned()[1..].to_string();
                let mut params: HashMap<String, String> = HashMap::new();
                let param_pairs: Vec<&str> = query.split('&').collect();
                for pair in param_pairs {
                    let mut iter = pair.split('=');
                    params.insert(iter.next().ok_or(error())?.to_string(), iter.next().ok_or(error())?.to_string());
                }
                (Some(query), Some(params))
            }
        };
        let fragment: Option<String> = captures.name("fragment").filter(|s| !s.as_str().is_empty()).map(|f| f.as_str().to_owned()[1..].to_string());
        Ok(DidUri{id, method, path, query, fragment, params})
    }
    pub fn did(&self) -> Did {
        Did{id: self.id.clone(), method: self.method.clone()}
    }
}

impl std::fmt::Display for DidUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)?;
        if let Some(path) = &self.path { write!(f, "{}", path)?; }
        if let Some(query) = &self.query { write!(f, "?{}", query)?; }
        if let Some(fragment) = &self.fragment { write!(f, "#{}", fragment)?; }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Type {
    Discoverable,
    Organization,
    Government,
    Corporation,
    LocalBusiness,
    SoftwarePackage,
    WebApp,
    FinancialInstitution
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Service {
    pub id: Url,
    pub types: Vec<String>,
    pub service_endpoints: Vec<Url>,
    pub enc: Vec<String>,
    pub sig: Vec<String>
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Purpose {Auth, Asm, Agm, Inv, Del}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DidKey {
    id: String,
    thumbprint_id: bool,
    public_key: Box<dyn traits::PublicKey>,
    purposes: Vec<Purpose>,
    controller: Option<Did> //Defaults to its attached Did
}

impl DidKey {
    pub fn id(&self) -> &String { &self.id }
    //pub fn public_key(&self) -> &dyn traits::PublicKey { self.public_key.as_ref() }
    pub fn public_key(&self) -> &Box<dyn traits::PublicKey> { &self.public_key }
    pub fn purposes(&self) -> &Vec<Purpose> { &self.purposes }
    pub fn controller(&self) -> &Option<Did> { &self.controller }

    pub fn thumbprint(&self) -> Result<String, Error> { Ok(if self.thumbprint_id { self.id.clone() } else {self.public_key.thumbprint()?}) }

    pub fn new(id: Option<String>, public_key: Box<dyn traits::PublicKey>, purposes: Vec<Purpose>, controller: Option<Did>) -> Result<Self, Error> {
        let (id, thumbprint_id) = match id {
            None => (public_key.thumbprint()?, true),
            Some(id) => (id, false)
        };
        if (purposes.contains(&Purpose::Auth) || purposes.contains(&Purpose::Asm)) && !public_key.curve().supports_signing() {
            return Err(Error::Unsupported("Purpose::Auth||Purpose::Asm (Signing)".to_string(), format!("the public_key curve({})", public_key.curve())));
        }
        if purposes.contains(&Purpose::Agm) && !public_key.curve().supports_ecies() {
            return Err(Error::Unsupported("Purpose::Agm(Ecies)".to_string(), format!("the public_key curve({})", public_key.curve())));
        }
        Ok(DidKey{id, thumbprint_id, public_key, purposes, controller})
    }
}

impl PartialEq for DidKey {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id) &&
        self.thumbprint_id.eq(&other.thumbprint_id) &&
        self.public_key.to_vec().eq(&other.public_key.to_vec()) &&
        self.purposes.eq(&other.purposes) &&
        self.controller.eq(&other.controller)
    }
}


#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Keys {
    keys: HashMap<String, DidKey>
}

impl Keys {
    pub fn new() -> Keys { Keys::default() }

    pub fn insert(&mut self, key: &DidKey) -> Result<(), Error> {
        if &key.id == "0" { return Err(Error::Unsupported("Store identity keys".to_string(), "Keys".to_string())); }
        if self.keys.get(&key.id).is_some() { return Err(Error::Requires("Keys.insert".to_string(), "key.id is unique".to_string())); }
        self.keys.insert(key.id.clone(), key.clone());
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&DidKey> { self.keys.get(id) }
    pub fn keys(&self) -> Vec<&DidKey> { self.keys.values().collect() }
}
