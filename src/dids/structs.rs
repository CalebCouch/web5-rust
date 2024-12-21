use super::Error;
use super::traits::{DidResolver, DidDocument};
use super::DhtDocument;
use crate::common::Schemas;
use simple_crypto::{SecretKey, PublicKey, Hashable};
use std::collections::BTreeMap;
use schemars::schema::Schema;
use serde::{Deserialize, Serialize};
use schemars::gen::SchemaGenerator;
use simple_database::{KeyValueStore, Indexable};
use schemars::JsonSchema;
use regex::Regex;
use url::Url;
use chrono::{DateTime, Utc};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct Endpoint(pub Did, pub Url);

impl Default for Endpoint {
    fn default() -> Self {
        Endpoint(Did::default(), Url::parse("https://example.net").unwrap())
    }
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} : {}", self.0, self.1)
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct Did {
    pub method: DidMethod,
    pub id: String,
}

impl Did {
    pub fn new(method: DidMethod, id: String) -> Self {
        Did{method, id}
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }
}

impl Hashable for Did {}

impl JsonSchema for Did {
    fn schema_name() -> String {"Did".to_string()}
    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        Schemas::regex(did_pattern())
    }
}

impl Indexable for Did {
    const PRIMARY_KEY: &'static str = "did";
    fn primary_key(&self) -> Vec<u8> {serde_json::to_vec(&self).unwrap()}
}

impl Default for Did {
    fn default() -> Self {
        Did{method: DidMethod::default(), id: "*****".to_string()}
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}

impl std::str::FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = || Error::parse("Did", s);
        let captures = Regex::new(&did_pattern())?.captures(s).ok_or(error())?;
        let method = DidMethod::from_str(captures.name("method").ok_or(error())?.as_str())?;
        let id = captures.name("id").ok_or(error())?.as_str().to_owned();
        Ok(Did{id, method})
    }
}

impl std::fmt::Debug for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:...{}", self.method, &self.id[..5])
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub enum DidMethod {
    #[default]
    DHT
}

impl std::fmt::Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DHT => write!(f, "dht")
        }
    }
}

impl std::str::FromStr for DidMethod {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "dht" => DidMethod::DHT,
            _ => return Err(Error::parse("DidMethod", s))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct DidUri {
    pub id: String,
    pub method: DidMethod,
    pub path: Option<String>,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub params: Option<BTreeMap<String, String>>
}

impl DidUri {
    pub fn new(
        id: String,
        method: DidMethod,
        path: Option<String>,
        query: Option<String>,
        fragment: Option<String>,
        params: Option<BTreeMap<String, String>>
    ) -> DidUri {
        DidUri{id, method, path, query, fragment, params}
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

impl std::str::FromStr for DidUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = || Error::parse("DidUri", s);
        let captures = Regex::new(&did_uri_pattern())?.captures(s).ok_or(error())?;
        let method = DidMethod::from_str(captures.name("method").filter(|s| !s.as_str().is_empty()).ok_or(error())?.as_str())?;
        let id: String = captures.name("id").filter(|s| !s.as_str().is_empty()).ok_or(error())?.as_str().to_owned();
        let path: Option<String> = captures.name("path").filter(|s| !s.as_str().is_empty()).map(|p| p.as_str().to_owned());
        let (query, params): (Option<String>, Option<BTreeMap<String, String>>) = match captures.name("query").filter(|s| !s.as_str().is_empty()) {
            None => (None, None),
            Some(q) => {
                let query = q.as_str().to_owned()[1..].to_string();
                let mut params: BTreeMap<String, String> = BTreeMap::new();
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
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(serde_with::SerializeDisplay)]
#[derive(serde_with::DeserializeFromStr)]
pub struct DidKeyUri {
    did: Did,
    id: String
}

impl DidKeyUri {
    pub fn id(&self) -> String {self.id.clone()}
    pub fn did(&self) -> Did {self.did.clone()}

    pub fn new(did: Did, id: &str) -> Self {
        DidKeyUri{did, id: id.to_string()}
    }
}

impl std::fmt::Display for DidKeyUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.did, self.id)?;
        Ok(())
    }
}

impl std::str::FromStr for DidKeyUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let error = || Error::parse("DidKeyUri", s);
        //TODO: use regex
        let split: Vec<&str> = s.split('#').collect();
        Ok(DidKeyUri{
            did: Did::from_str(split.first().ok_or(error())?)?,
            id: split.get(1).ok_or(error())?.to_string()
        })
    }
}


#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum DidType {
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
pub struct DidService {
    pub id: String,
    pub types: Vec<String>,
    pub service_endpoints: Vec<String>,
    pub keys: Vec<String>,
}

impl DidService {
    pub fn new_dwn(service_endpoints: Vec<String>) -> Self {
        DidService{
            id: "dwn".to_string(),
            types: vec!["DecentralizedWebNode".to_string()],
            service_endpoints,
            keys: vec!["key".to_string()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum DidKeyPurpose {Auth, Asm, Agm, Inv, Del}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DidKey {
    pub id: String,
    pub did: Did,
    pub public_key: PublicKey,
    pub purposes: Vec<DidKeyPurpose>,
    pub controller: Option<Did> //Defaults to its attached Did
}

impl DidKey {
    pub fn thumbprint(&self) -> String {
        self.public_key.thumbprint()
    }
    pub fn new(
        id: Option<String>,
        did: Did,
        public_key: PublicKey,
        purposes: Vec<DidKeyPurpose>,
        controller: Option<Did>
    ) -> Self {
        let id = if let Some(id) = id {id} else {public_key.thumbprint()};
        DidKey{id, did, public_key, purposes, controller}
    }
    pub fn key_uri(&self) -> DidKeyUri {DidKeyUri::new(self.did.clone(), &self.id)}
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct DidKeyPair {
    pub secret: SecretKey,
    pub public: DidKey
}

impl DidKeyPair {
    pub fn owner(&self) -> &Did {&self.public.did}
    pub fn new(
        secret: SecretKey,
        public: DidKey
    ) -> Result<Self, Error> {
        Ok(DidKeyPair{secret, public})
    }
}

#[derive(Debug, Clone)]
pub struct DefaultDidResolver {
    cache: Box<dyn KeyValueStore>
}

impl DefaultDidResolver {
    pub async fn new<KVS: KeyValueStore + 'static>(path: Option<PathBuf>) -> Result<Self, Error> {
        let path = path.unwrap_or(PathBuf::from("DefaultDidResolver"));
        Ok(DefaultDidResolver{
            cache: Box::new(KVS::new(path).await?)
        })
    }
}

#[async_trait::async_trait]
impl DidResolver for DefaultDidResolver {
    async fn resolve(&self, did: &Did) -> Result<Option<Box<dyn DidDocument>>, Error> {
        let bytes = serde_json::to_vec(did)?;
        if let Some((time, doc)) = self.cache.get(&bytes).await?.as_ref().map(|b|
            serde_json::from_slice::<(DateTime<Utc>, Box<dyn DidDocument>)>(b)
        ).transpose()? {
            if Utc::now().timestamp() > time.timestamp()+900 {
                self.cache.delete(&bytes).await?;
            } else {
                return Ok(Some(doc));
            }
        }
        log::info!("Resolving did: {}", did);
        let doc = match did.method {
            DidMethod::DHT => DhtDocument::resolve(&did.id).await?.map(|m|
                Box::new(m) as Box<dyn DidDocument>
            )
        };

        if let Some(doc) = doc.clone() {
            self.cache.set(&bytes, &serde_json::to_vec(&(Utc::now(), doc))?).await?;
        }
        Ok(doc)
    }
}

