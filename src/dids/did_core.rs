use super::error::Error;
//use crate::crypto::PublicKey;

//use http::uri::Uri as HttpUri;
//use crate::crypto::jwk::Jwk;
//use crate::crypto::jwk::compute_jwk_thumbprint;
//use super::utils::extract_did_fragment;

//use std::collections::HashMap;
use serde::{Deserialize, Serialize};
//use regex::Regex;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum DidMethod {
    DHT
}

impl std::fmt::Display for DidMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DHT => write!(f, "dht")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Did {
    pub id: String,
    pub method: DidMethod
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:{}:{}", self.method, self.id)
    }
}














//  fn method_pattern() -> String {"([a-z0-9]+)".to_string()}
//  fn pct_encoded_pattern() -> String {"(?:%[0-9a-fA-F]{2})".to_string()}
//  fn id_char_pattern() -> String {format!("(?:[a-zA-Z0-9._-]|{})", pct_encoded_pattern())}
//  fn method_id_pattern() -> String {format!("((?:{}*:)*({}+))", id_char_pattern(), id_char_pattern())}
//  fn path_pattern() -> String {"(/[^#?]*)?".to_string()}
//  fn query_pattern() -> String {"([?][^#]*)?".to_string()}
//  fn fragment_pattern() -> String {"(#.*)?".to_string()}
//  fn did_pattern() -> String { format!("did:(?<method>{}):(?<id>{})", method_pattern(), method_id_pattern()) }
//  fn path_query_frag() -> String { format!("(?<path>{})(?<query>{})(?<fragment>{})", path_pattern(), query_pattern(), fragment_pattern()) }
//  fn did_uri_pattern() -> String { format!("^{}{}$", did_pattern(), path_query_frag()) }

//  #[derive(Default, Clone, PartialEq, Deserialize, Serialize)]
//  pub struct Did {
//      pub id: String,
//      pub method: String
//  }

//  impl Did {
//      pub fn new(method: String, id: String) -> Did {
//          Did{method, id}
//      }

//      pub fn parse(did: String) -> Result<Did, Error> {
//          let error = || Error::Parse("did".to_string(), did.clone());
//          let captures = Regex::new(&did_pattern())?.captures(&did).ok_or(error())?;
//          let method: String = captures.name("method").ok_or(error())?.as_str().to_owned();
//          let id: String = captures.name("id").ok_or(error())?.as_str().to_owned();
//          Ok(Did::new(id, method))
//      }
//  }


//  #[derive(Clone, Deserialize, Serialize)]
//  pub struct Uri {
//      pub scheme: Option<String>,
//      pub authority: Option<String>,
//      pub path: String,
//      pub query: Option<String>,
//      pub fragment: Option<String>
//  }

//  impl Uri {
//      pub fn new(scheme: Option<String>, authority: Option<String>, path: String, query: Option<String>, fragment: Option<String>) -> Uri {
//          Uri{scheme, authority, path, query, fragment}
//      }
//      pub fn parse(uri: String) -> Result<Uri, Error> {
//          let parsed_uri = uri.parse::<HttpUri>().or(Err(Error::Parse("uri".to_string(), uri.clone())))?;
//          let scheme = parsed_uri.scheme_str().map(|s| s.to_string());
//          let authority = parsed_uri.authority().map(|a| a.as_str().to_string());
//          let path = parsed_uri.path().to_string();
//          let query = parsed_uri.query().map(|q| q.to_string());
//          let fragment = uri.split('#').collect::<Vec<&str>>().pop().map(|f| f.to_string());
//          Ok(Uri{scheme, authority, path, query, fragment})
//      }
//  }



//  #[derive(Clone, Deserialize, Serialize)]
//  pub struct DidUri {
//      pub id: String,
//      pub method: String,
//      pub path: Option<String>,
//      pub query: Option<String>,
//      pub fragment: Option<String>,
//      pub params: Option<HashMap<String, String>>
//  }

//  impl DidUri {
//      pub fn new(method: String, id: String, path: Option<String>, query: Option<String>, fragment: Option<String>, params: Option<HashMap<String, String>>) -> DidUri {
//          DidUri{method, id, path, query, fragment, params}
//      }

//      pub fn parse(did_uri: String) -> Result<DidUri, Error> {
//          let error = || Error::Parse(did_uri.clone(), "did_uri".to_string());
//          let captures = Regex::new(&did_uri_pattern())?.captures(&did_uri).ok_or(error())?;
//          let method: String = captures.name("method").ok_or(error())?.as_str().to_owned();
//          let id: String = captures.name("id").ok_or(error())?.as_str().to_owned();
//          let path: Option<String> = captures.name("path").map(|p| p.as_str().to_owned());
//          let (query, params): (Option<String>, Option<HashMap<String, String>>) = match captures.name("query") {
//              None => (None, None),
//              Some(q) => {
//                  let query = q.as_str().to_owned()[1..].to_string();
//                  let mut params: HashMap<String, String> = HashMap::new();
//                  let param_pairs: Vec<&str> = query.split('&').collect();
//                  for pair in param_pairs {
//                      let mut iter = pair.split('=');
//                      params.insert(iter.next().ok_or(error())?.to_string(), iter.next().ok_or(error())?.to_string());
//                  }
//                  (Some(query), Some(params))
//              }
//          };
//          let fragment: Option<String> = captures.name("fragment").map(|f| f.as_str().to_owned()[1..].to_string());
//          Ok(DidUri::new(id, method, path, query, fragment, params))
//      }

//      pub fn did(&self) -> Did {
//          Did::new(self.id.clone(), self.method.clone())
//      }
//  }

//  impl std::fmt::Display for DidUri {
//      fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//          write!(f, "did:{}:{}", self.method, self.id)?;
//          if let Some(path) = &self.path { write!(f, "{}", path)?; }
//          if let Some(query) = &self.query { write!(f, "?{}", query)?; }
//          if let Some(fragment) = &self.fragment { write!(f, "#{}", fragment)?; }
//          Ok(())
//      }
//  }

//  #[derive(Default, Deserialize, Serialize)]
//  pub struct DidMetadata {
//      pub created: Option<String>,
//      pub updated: Option<String>,
//      pub published: Option<bool>,
//      pub deactivated: Option<bool>,
//      pub version_id: Option<String>,
//      pub next_update: Option<String>,
//      pub canonical_id: Option<String>,
//      pub next_version_id: Option<String>,
//      pub equivalent_id: Vec<String>,
//      pub types: Vec<DidType>,
//  }

//  #[derive(Deserialize, Serialize, Debug)]
//  pub enum DidType {
//      Discoverable,
//      Organization,
//      Government,
//      Corporation,
//      LocalBusiness,
//      SoftwarePackage,
//      WebApp,
//      FinancialInstitution
//  }

//  #[derive(Deserialize, Serialize)]
//  pub struct DidDocument {
//      pub did: Did,
//      pub also_known_as: Vec<Uri>,
//      pub controllers: Vec<Did>,
//      pub services: Vec<DidService>,

//      vms: HashMap<String, DidVerificationMethod>
//  }

//  impl DidDocument {
//      pub fn verification_methods(&self) -> Vec<DidVerificationMethod> { self.vms.clone().into_values().collect() }

//      pub fn insert(&mut self, vm: DidVerificationMethod) -> Result<(), Error> {
//          if self.vms.insert(vm.id.to_string(), vm).is_some() {
//              return Err(Error::NonUniqueId());
//          }
//          Ok(())
//      }

//      pub fn new(did: Did, also_known_as: Vec<Uri>, controllers: Vec<Did>, verification_methods: Vec<DidVerificationMethod>, services: Vec<DidService>) -> Result<Self, Error> {
//          let mut document = DidDocument{did, also_known_as, controllers, services, vms: HashMap::new()};
//          for vm in verification_methods { document.insert(vm)?; }
//          Ok(document)
//      }

//      pub fn new_didless(also_known_as: Vec<Uri>, controllers: Vec<Did>, verification_methods: Vec<DidVerificationMethod>, services: Vec<DidService>) -> Result<Self, Error> {
//          DidDocument::new(Did::default(), also_known_as, controllers, verification_methods, services)
//      }
//  }

//  #[derive(Clone, Deserialize, Serialize)]
//  pub struct DidVerificationMethod {
//      pub id: DidUri,
//      pub r#type: String,
//      pub controller: Did,
//      pub public_key: PublicKey,
//      pub public_key_multibase: Option<String>,
//      pub purposes: Vec<DidVerificationRelationship>
//  }

//  #[derive(Clone, PartialEq, Deserialize, Serialize)]
//  pub enum DidVerificationRelationship {
//      Authentication,
//      AssertionMethod,
//      KeyAgreement,
//      CapabilityInvocation,
//      CapabilityDelegation
//  }

//  #[derive(Clone, Deserialize, Serialize)]
//  pub struct DidService {
//      pub id: Uri,
//      pub r#type: String,
//      pub service_endpoints: Vec<Uri>,
//      pub custom_properties: HashMap<String, String>
//  }

//  //  pub struct CustomProperties {
//  //      existing_properties: Vec<String>,
//  //      map: HashMap<String, String>
//  //  }

//  //  impl CustomProperties {
//  //      pub fn new(existing_properties, Vec<String>) -> CustomProperties {
//  //          CustomProperties{existing_properties, map: HashMap::new()}
//  //      }

//  //      pub fn insert(&mut self, key: String, value: String) -> Result<String, Error> {
//  //         if self.existing_properties.contains(key) { return Err(Error::ExistingProperty()); }
//  //          self.map.insert(key, value)
//  //      }

//  //      pub fn map(&self) -> &HashMap<String, String> {
//  //          self.map
//  //      }
//  //  }



//  //  impl DidService {
//  //      pub fn new(id: Uri, r#type: String, service_endpoints: Vec<Uri>) -> DidService {
//  //          DidService{id, r#type, service_endpoints, custom_properties: CustomProperties::new(vec!["id", "t", "se"])} //These listed properties are the DNS encoded version of the DidService properties
//  //      }
//  //  }







//  //  #[derive(Clone, Deserialize, Serialize)]
//  //  pub enum DidServiceEndpoint {
//  //      Endpoints(HashMap<String, String>)
//  //  }




//  //  pub struct DidDereferencingMetadata  {
//  //    content_type: Option<String>,
//  //    error: Option<String>,

//  //    //TODO
//  //    //[key: string]: any;
//  //  }

//  //  pub struct DidDereferencingOptions {
//  //      accept: Option<String>,
//  //      //TODO
//  //      //[key: string]: any;
//  //  }

//  //  pub struct DidDereferencingResult {
//  //      dereferencing_metadata: DidDereferencingMetadata,
//  //      content_stream: Option<DidResource>,
//  //      content_metadata: DidDocumentMetadata,
//  //  }



//  //  impl DidDocument {
//  //      pub fn get_verification_method_by_relationship(&self, relationship: &DidVerificationRelationship) -> &Option<Vec<DidVerificationMethod>> {
//  //          match relationship {
//  //              DidVerificationRelationship::Authentication => &self.authentication,
//  //              DidVerificationRelationship::AssertionMethod => &self.assertion_method,
//  //              DidVerificationRelationship::KeyAgreement => &self.key_agreement,
//  //              DidVerificationRelationship::CapabilityInvocation => &self.capability_invocation,
//  //              DidVerificationRelationship::CapabilityDelegation => &self.capability_delegation,
//  //          }
//  //      }

//  //      pub fn get_verification_methods(&self) -> Vec<&DidVerificationMethod> {
//  //          let mut vms: Vec<&DidVerificationMethod> = Vec::new();
//  //          if let Some(vm) = &self.verification_method {
//  //              vms.extend(vm);
//  //          }
//  //          for relationship in DidVerificationRelationship::all() {
//  //              if let Some(vm) = self.get_verification_method_by_relationship(&relationship) {
//  //                  vms.extend(vm);
//  //              }
//  //          }
//  //          vms
//  //      }

//  //      pub fn get_verification_method_by_key(&self, public_key_jwk: Option<Jwk>, public_key_multibase: Option<String>) -> Result<Option<DidVerificationMethod>, Error> {
//  //          let verification_methods: Vec<&DidVerificationMethod> = self.get_verification_methods();
//  //          if verification_methods.is_empty() { return Err(Error::VerificationMethodNotFound()); }

//  //          for vm in verification_methods {
//  //              if public_key_jwk.is_some() && vm.public_key_jwk.is_some() {
//  //                  if let Ok(thumbprint) = compute_jwk_thumbprint(public_key_jwk.as_ref().unwrap()) {
//  //                      if let Ok(vm_thumbprint) = compute_jwk_thumbprint(vm.public_key_jwk.as_ref().unwrap()) {
//  //                          if thumbprint == vm_thumbprint {
//  //                              return Ok(Some(vm.clone()));
//  //                          }
//  //                      }
//  //                  }
//  //              } else if let Some(public_key_multibase) = &public_key_multibase {
//  //                  if let Some(vm_public_key_multibase) = &vm.public_key_multibase {
//  //                      if public_key_multibase == vm_public_key_multibase {
//  //                          return Ok(Some(vm.clone()));
//  //                      }
//  //                  }
//  //              }
//  //          }
//  //          Ok(None)
//  //      }

//  //      pub fn get_verification_method_types(&self) -> Vec<String> {
//  //          self.get_verification_methods().into_iter().map(|vm| vm.r#type.clone()).collect()
//  //      }

//  //      pub fn get_verification_relationships_by_id(&self, method_id: String) -> Vec<DidVerificationRelationship> {
//  //          let method_id_fragment = extract_did_fragment(method_id);
//  //          DidVerificationRelationship::all().into_iter().filter(|relationship| {
//  //              if let Some(vms) = self.get_verification_method_by_relationship(relationship) {
//  //                  !vms.iter().filter(|vm| extract_did_fragment(vm.id.to_string()) == method_id_fragment).collect::<Vec<&DidVerificationMethod>>().is_empty()
//  //              } else { false }
//  //          }).collect()
//  //      }

//  //      pub fn get_services(&self, id: Option<String>, r#type: Option<String>) -> Vec<DidService> {
//  //          if let Some(services) = self.service.clone() {
//  //              services.into_iter().filter(|s| {
//  //                  if let Some(id) = &id {
//  //                      if &s.id != id {return false;}
//  //                  }
//  //                  if let Some(r#type) = &r#type {
//  //                      if &s.r#type != r#type {return false;}
//  //                  }
//  //                  true
//  //              }).collect()
//  //          } else { Vec::new() }
//  //      }
//  //  }




//  //  #[derive(Deserialize, Serialize)]
//  //  pub struct DidResolutionMetadata {
//  //      pub content_type: Option<String>,
//  //      pub error: Option<String>,
//  //      //TODO
//  //      //[key: string]: any;
//  //  }

//  //  pub struct DidResolutionOptions {
//  //      pub accept: Option<String>,
//  //      //TODO
//  //      //[key: string]: any;
//  //  }

//  //  #[derive(Deserialize, Serialize)]
//  //  pub struct DidResolutionResult {
//  //      //TODO
//  //      //'@context'?: 'https://w3id.org/did-resolution/v1' | string | (string | Record<string, any>)[];
//  //      pub did_resolution_metadata: DidResolutionMetadata,
//  //      //TODO
//  //      pub did_document: Option<DidDocument>,
//  //      pub did_document_metadata: Option<DidDocumentMetadata>
//  //  }

//  //  pub enum DidResource {
//  //      DidDocument(DidDocument),
//  //      DidService(DidService),
//  //      DidVerificationMethod(DidVerificationMethod)
//  //  }





//  //  impl DidVerificationRelationship {
//  //      pub fn all() -> Vec<DidVerificationRelationship> {
//  //          vec![
//  //              DidVerificationRelationship::Authentication,
//  //              DidVerificationRelationship::AssertionMethod,
//  //              DidVerificationRelationship::KeyAgreement,
//  //              DidVerificationRelationship::CapabilityInvocation,
//  //              DidVerificationRelationship::CapabilityDelegation
//  //          ]
//  //      }
//  //  }

