use regex::Regex;
use super::error::Error;
use std::collections::HashMap;

pub struct Did {

    /**
     * A string representation of the DID.
     *
     * A DID is a URI composed of three parts: the scheme `did:`, a method identifier, and a unique,
     * method-specific identifier specified by the DID method.
     *
     * @example
     * did:dht:h4d3ixkwt6q5a455tucw7j14jmqyghdtbr6cpiz6on5oxj5bpr3o
     */
    pub uri: String,

    /**
     * The name of the DID method.
     *
     * Examples of DID method names are `dht`, `jwk`, and `web`, among others.
     */
    pub method: String,

    /**
     * The DID method identifier.
     *
     * @example
     * h4d3ixkwt6q5a455tucw7j14jmqyghdtbr6cpiz6on5oxj5bpr3o
    */
    pub id: String,

    /**
     * Optional path component of the DID URI.
     *
     * @example
     * did:web:tbd.website/path
     */
    pub path: Option<String>,

    /**
     * Optional query component of the DID URI.
     *
     * @example
     * did:web:tbd.website?versionId=1
     */
    pub query: Option<String>,

    /**
     * Optional fragment component of the DID URI.
     *
     * @example
     * did:web:tbd.website#key-1
     */
    pub fragment: Option<String>,

    /**
      * Optional query parameters in the DID URI.
      *
      * @example
      * did:web:tbd.website?service=files&relativeRef=/whitepaper.pdf
      */
    pub params: Option<HashMap<String, String>>,
}

impl Did {
    /** Regular expression pattern for matching the method component of a DID URI. */
    fn method_pattern() -> String {"([a-z0-9]+)".to_string()}

    /** Regular expression pattern for matching percent-encoded characters in a method identifier. */
    fn pct_encoded_pattern() -> String {"(?:%[0-9a-fA-F]{2})".to_string()}

    /** Regular expression pattern for matching the characters allowed in a method identifier. */
    fn id_char_pattern() -> String {format!("(?:[a-zA-Z0-9._-]|{})", Did::pct_encoded_pattern())}

    /** Regular expression pattern for matching the method identifier component of a DID URI. */
    fn method_id_pattern() -> String {format!("((?:{}*:)*({}+))", Did::id_char_pattern(), Did::id_char_pattern())}

    /** Regular expression pattern for matching the path component of a DID URI. */
    fn path_pattern() -> String {"(/[^#?]*)?".to_string()}

    /** Regular expression pattern for matching the query component of a DID URI. */
    fn query_pattern() -> String {"([?][^#]*)?".to_string()}

    /** Regular expression pattern for matching the fragment component of a DID URI. */
    fn fragment_pattern() -> String {"(#.*)?".to_string()}

    /** Regular expression pattern for matching all of the components of a DID URI. */
    fn did_uri_pattern() -> Result<Regex, Error> { 
        Ok(Regex::new(&format!(
            "^did:(?<method>{}):(?<id>{})(?<path>{})(?<query>{})(?<fragment>{})$",
            Did::method_pattern(), 
            Did::method_id_pattern(), 
            Did::path_pattern(), 
            Did::query_pattern(), 
            Did::fragment_pattern()
        ))?)
    }

    /**
     * Constructs a new `Did` instance from individual components.
     *
     * @param params - An object containing the parameters to be included in the DID URI.
     * @param params.method - The name of the DID method.
     * @param params.id - The DID method identifier.
     * @param params.path - Optional. The path component of the DID URI.
     * @param params.query - Optional. The query component of the DID URI.
     * @param params.fragment - Optional. The fragment component of the DID URI.
     * @param params.params - Optional. The query parameters in the DID URI.
     */
    pub fn new(method: String, id: String, path: Option<String>, query: Option<String>, fragment: Option<String>, params: Option<HashMap<String, String>>) -> Did {
        Did{uri: format!("did:{}:{}", method, id), method, id, path, query, fragment, params}
    }

    /**
     * Parses a DID URI string into its individual components.
     *
     * ```rs
     * let did = Did::parse('did:example:123?service=agent&relativeRef=/credentials#degree');
     *
     * println!(did.uri)      // Output: 'did:example:123'
     * println!(did.method)   // Output: 'example'
     * println!(did.id)       // Output: '123'
     * println!(did.query)    // Output: 'service=agent&relativeRef=/credentials'
     * println!(did.fragment) // Output: 'degree'
     * println!(did.params)   // Output: { service: 'agent', relativeRef: '/credentials' }
     * ```
     *
     * @params didUri - The DID URI string to be parsed.
     * @returns A `Did` object representing the parsed DID URI, or `null` if the input string is not a valid DID URI.
     */
    pub fn parse(did_uri: String) -> Result<Option<Did>, Error> {
        if let Some(captures) = Did::did_uri_pattern()?.captures(&did_uri) {
              if let Some(method) = captures.name("method") {
                if let Some(id) = captures.name("id") {
                    let mut did: Did = Did::new(method.as_str().to_owned(), id.as_str().to_owned(), None, None, None, None);
                    if let Some(path) = captures.name("path") {
                        did.path = Some(path.as_str().to_owned());
                    }
                    if let Some(query) = captures.name("query") {
                        let query = query.as_str().to_owned()[1..].to_string();
                        let mut params: HashMap<String, String> = HashMap::new();
                        let param_pairs: Vec<&str> = query.split('&').collect();
                        for pair in param_pairs {
                            let mut iter = pair.split('=');
                            params.insert(iter.next().ok_or(Error::QueryParsing())?.to_string(), iter.next().ok_or(Error::QueryParsing())?.to_string());
                        }
                        did.query = Some(query);
                        did.params = Some(params);
                    }
                    if let Some(fragment) = captures.name("fragment") {
                        did.fragment = Some(fragment.as_str().to_string()[1..].to_string());
                    }
                    return Ok(Some(did));
                }
            }
        }
        Ok(None)
    }
}
