use super::error::Error;

use crate::common::Convert;
use crate::common::traits::KeyValueStore;

use crate::crypto::ed25519::Ed25519;
use crate::crypto::traits::{CryptoAlgorithm, ToPublicKey};
use crate::crypto::{ed25519, PublicKey, SecretKey, LocalKeyStore};

use super::dns_packet::DhtDns;
use super::pkarr::PkarrRelay;
use super::did_core::{DidMethod, Did};
use url::Url;


use serde::{Deserialize, Serialize};

const DEFAULT_GATEWAY_URI: &str = "https://diddht.tbddev.org";


#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Service {
    pub id: Url,
    pub r#type: Vec<String>,
    pub service_endpoints: Vec<Url>,
    pub enc: Vec<String>,
    pub sig: Vec<String>
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Purpose {Auth, Asm, Agm, Inv, Del}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Key {
    pub id: Option<String>,
    pub public_key: PublicKey,
    pub purposes: Vec<Purpose>,
    pub controller: Option<Did>
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct IdentityKey {
    pub public_key: ed25519::PublicKey,
    pub purposes: Vec<Purpose>,
    pub controller: Option<Did>
}

impl IdentityKey {
    pub fn to_key(&self) -> Key {
        Key{
            id: Some("0".to_string()),
            public_key: PublicKey::Ed(self.public_key),
            purposes: self.purposes.clone(),
            controller: self.controller.clone()
        }
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
pub struct DidDht {
    pub identity_key: IdentityKey,
    pub also_known_as: Vec<Url>,
    pub controllers: Vec<Did>,
    pub services: Vec<Service>,
    pub keys: Vec<Key>,
    pub types: Vec<Type>
}

impl DidDht {
    pub fn method() -> DidMethod { DidMethod::DHT }
    pub fn id (&self) -> Result<String, Error> {
        Ok(Convert::ZBase32.encode(self.identity_key.public_key.as_bytes())?)
    }

    pub fn new<KVS: KeyValueStore<PublicKey, SecretKey>>(key_store: &mut LocalKeyStore<KVS>) -> Result<Self, Error> {
        Self::create(key_store, vec![], vec![], vec![], vec![], vec![])
    }

    pub fn create<KVS: KeyValueStore<PublicKey, SecretKey>>(
        key_store: &mut LocalKeyStore<KVS>,
        also_known_as: Vec<Url>,
        controllers: Vec<Did>,
        services: Vec<Service>,
        keys: Vec<Key>,
        types: Vec<Type>
    ) -> Result<Self, Error> {
        let secret_key: ed25519::SecretKey = Ed25519::generate_key();
        let public_key: ed25519::PublicKey = secret_key.public_key();
        key_store.store_key(&SecretKey::Ed(secret_key))?;
        let identity_key = IdentityKey{
            public_key,
            purposes: vec![Purpose::Auth, Purpose::Asm, Purpose::Del, Purpose::Inv],
            controller: None
        };
        Ok(DidDht{identity_key, also_known_as, controllers, services, keys, types})
    }

    pub async fn publish<KVS: KeyValueStore<PublicKey, SecretKey>>(
        &self,
        key_store: &LocalKeyStore<KVS>,
        gateway: Option<Url>
    ) -> Result<(), Error> {
        let gateway = gateway.unwrap_or(Url::parse(DEFAULT_GATEWAY_URI)?);
        let public_key = self.identity_key.public_key;
        if let Some(SecretKey::Ed(secret_key)) = key_store.get_key(&PublicKey::Ed(public_key))? {
            let id = self.id()?;
            let url = gateway.join(&id)?;
            PkarrRelay::put(
                url,
                DhtDns::to_bytes(self, vec![gateway])?,
                secret_key
            ).await
        } else { Err(Error::KeyNotFound()) }
    }

    pub async fn resolve(gateway: Option<Url>, public_key: ed25519::PublicKey) -> Result<(), Error> {
        let gateway = gateway.unwrap_or(Url::parse(DEFAULT_GATEWAY_URI)?);
        let id = Convert::ZBase32.encode(public_key.as_bytes())?;

        let packet = PkarrRelay::get(gateway.join(&id)?, public_key).await?;
        DhtDns::from_bytes(&packet[64+8..], id)?;
        Ok(())
    }
}

//  impl DidDht {
//      pub fn id_from_key(key: ed25519::PublicKey) -> Result<String, Error> { Ok(Convert::ZBase32.encode(key.as_bytes())?) }
//      pub fn method() -> String { "dht".to_string() }

//      pub fn create<KVS: KeyValueStore<PublicKey, SecretKey>>(
//          key_store: &mut LocalKeyStore<KVS>,
//          document: DidDocument,
//          types: Vec<DidType>,
//          gateway_uri: Option<Uri>,
//          publish: bool
//      ) -> Result<Self, Error> {
//          let secret_key: ed25519::SecretKey = Ed25519::generate_key();
//          let id_key: ed25519::PublicKey = secret_key.verifying_key();
//          key_store.store.set(PublicKey::Ed(id_key), SecretKey::Ed(secret_key))?;

//          let did = Did::new(Self::id_from_key(id_key)?, Self::method());
//          let mut document = document;
//          document.did = did;

//          let metadata = DidMetadata{types, .. DidMetadata::default()};

//          let did_dht = DidDht{id_key, document, metadata};

//          if publish {
//              did_dht.publish(gateway_uri)?;
//              //did_metadata = registrationResult.didDocumentMetadata;
//          }
//          Ok(did_dht)
//      }

//      pub fn publish<KVS: KeyValueStore<PublicKey, SecretKey>>(&self, key_store: &mut LocalKeyStore<KVS>, gateway_uri: Option<Uri>) -> Result<(), Error> {
//          let gateway_uris = if let Some(gateway) = gateway_uri { vec![gateway] } else { vec![] };
//          let dns_packet = self.to_dns_packet(gateway_uris)?;
//          let seq = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
//          let bencoded = serde_bencode::to_bytes(&Bep44Data{seq, v: dns_packet })?;
//          let v = bencoded[1..bencoded.len()-1].to_vec();
//          if v.len() > 1000 { return Err(Error::InvalidDidDocumentLength(v.len().to_string())); }
//          if let Some(secret_key) = key_store.get(&PublicKey::Ed(self.id_key))? {
//              let sig: = Ed25519::sign(secret_key, bencoded).as_bytes();//TODO: ZBase32???
//              let k = self.id_key.as_bytes();//TODO: ZBase32??? or raw
//              let bep_44_message = Bep44Message{k: public_key, seq, sig, v};
//              //return { k: publicKeyBytes, seq: sequenceNumber, sig: signature, v: encodedDnsPacket };
//          } else { return Err(Error::NoKeyFound()); }
//      }

//      pub fn to_dns_packet_bytes(&self, authoritative_gateway_uris: Vec<Uri>) -> Result<Vec<u8>, Error> {
//          let mut txt_records: HashMap<String, String> = HashMap::new();

//          if !self.document.also_known_as.is_empty() {
//              let also_known_as = self.document.also_known_as.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR);
//              txt_records.insert("_aka._did.".to_string(), also_known_as);
//          }

//          if !self.document.controllers.is_empty() {
//              let controllers = self.document.controllers.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR);
//              txt_records.insert("_cnt._did.".to_string(), controllers);
//          }

//          let mut root_record: Vec<String> = vec![format!("v={}", DID_DHT_SPECIFICATION_VERSION)];

//          let mut auth: Vec<String> = Vec::new();
//          let mut asm: Vec<String> = Vec::new();
//          let mut agm: Vec<String> = Vec::new();
//          let mut inv: Vec<String> = Vec::new();
//          let mut del: Vec<String> = Vec::new();
//          let vms = self.document.verification_methods();
//          if !vms.is_empty() {
//              let mut vm_ids: Vec<String> = Vec::new();
//              for (index, vm) in vms.iter().enumerate() {
//                  let dns_record_id = format!("k{}", index);
//                  vm_ids.push(dns_record_id.clone());

//                  //Verification Relationships
//                  if vm.purposes.contains(&DidVerificationRelationship::Authentication) { auth.push(dns_record_id.clone()); }
//                  if vm.purposes.contains(&DidVerificationRelationship::AssertionMethod) { asm.push(dns_record_id.clone()); }
//                  if vm.purposes.contains(&DidVerificationRelationship::KeyAgreement) { agm.push(dns_record_id.clone()); }
//                  if vm.purposes.contains(&DidVerificationRelationship::CapabilityInvocation) { inv.push(dns_record_id.clone()); }
//                  if vm.purposes.contains(&DidVerificationRelationship::CapabilityDelegation) { del.push(dns_record_id.clone()); }

//                  let key_index = key_to_index(&vm.public_key);
//                  let encoded_pubkey = Convert::Base64Url.encode(vm.public_key.as_bytes())?;
//                  let mut txt_data = vec![format!("t={}", key_index), format!("k={}", encoded_pubkey)];
//                  if let PublicKey::Ed(_) = vm.public_key {} else {
//                      txt_data.push(format!("a={}", key_algo_to_name(&vm.public_key)));
//                  }
//                  if vm.controller != self.document.did {
//                      txt_data.push(format!("c={}", vm.controller));
//                  }
//                  let txt_data = txt_data.join(PROPERTY_SEPARATOR);
//                  txt_records.insert(format!("_{}._did.", dns_record_id), txt_data);
//              }
//              root_record.push(format!("vm={}", vm_ids.join(VALUE_SEPARATOR)));
//              if !auth.is_empty() { root_record.push(format!("auth={}", auth.join(VALUE_SEPARATOR))); }
//              if !asm.is_empty() { root_record.push(format!("asm={}", asm.join(VALUE_SEPARATOR))); }
//              if !agm.is_empty() { root_record.push(format!("agm={}", agm.join(VALUE_SEPARATOR))); }
//              if !inv.is_empty() { root_record.push(format!("inv={}", inv.join(VALUE_SEPARATOR))); }
//              if !del.is_empty() { root_record.push(format!("del={}", del.join(VALUE_SEPARATOR))); }
//          }

//          if !self.document.services.is_empty() {
//              let mut service_ids: Vec<String> = Vec::new();
//              for (index, s) in self.document.services.iter().enumerate() {
//                  let dns_record_id = format!("s{}", index);
//                  service_ids.push(dns_record_id.clone());
//                  let mut data: HashMap<&str, String> = HashMap::new();
//                  data.insert("id", s.id.fragment.clone().ok_or(Error::NoServiceFragment())?);
//                  data.insert("t", s.r#type.clone());
//                  data.insert("se", s.service_endpoints.iter().map(|ep| ep.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR));
//                  for (key, value) in s.custom_properties.iter() {
//                      if !data.contains_key(key.as_str()) { //Ignore duplicates
//                          data.insert(key, value.to_string());
//                      }
//                  }
//                  let txt_data = data.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join(PROPERTY_SEPARATOR);
//                  txt_records.insert(format!("_{}._did.", dns_record_id), txt_data);
//              }
//              root_record.push(format!("svc={}", service_ids.join(VALUE_SEPARATOR)));
//          }

//          if !self.metadata.types.is_empty() {
//              let types = format!("id={}", self.metadata.types.iter().map(|t| Ok::<String, Error>(type_to_index(t)?.to_string())).collect::<Result<Vec<String>, Error>>()?.join(VALUE_SEPARATOR));
//              txt_records.insert("_typ._did.".to_string(), types);
//          }

//          let root_record = root_record.join(PROPERTY_SEPARATOR);
//          txt_records.insert(format!("_did.{}.", self.document.did.id), root_record);

//      }
//  }



//  //  // Create a signed BEP44 put message from the DNS packet.
//  //  const bep44Message = await DidDhtUtils.createBep44PutMessage({
//  //    dnsPacket,
//  //    publicKeyBytes : DidDhtUtils.identifierToIdentityKeyBytes({ didUri: did.uri }),
//  //    signer         : await did.getSigner({ methodId: '0' })
//  //  });

//  //  // Publish the DNS packet to the DHT network.
//  //  const putResult = await DidDhtDocument.pkarrPut({ gatewayUri, bep44Message });

//  //  // Return the result of processing the PUT operation, including the updated DID metadata with
//  //  // the version ID and the publishing result.
//  //  return {
//  //    didDocument         : did.document,
//  //    didDocumentMetadata : {
//  //      ...did.metadata,
//  //      published : putResult,
//  //      versionId : bep44Message.seq.toString()
//  //    },
//  //    didRegistrationMetadata: {}
//  //  };
//      

//  //    /**
//  //     * Instantiates a {@link BearerDid} object for the DID DHT method from a given {@link PortableDid}.
//  //     *
//  //     * This method allows for the creation of a `BearerDid` object using a previously created DID's
//  //     * key material, DID document, and metadata.
//  //     *
//  //     * @example
//  //     * ```ts
//  //     * // Export an existing BearerDid to PortableDid format.
//  //     * const portableDid = await did.export();
//  //     * // Reconstruct a BearerDid object from the PortableDid.
//  //     * const did = await DidDht.import({ portableDid });
//  //     * ```
//  //     *
//  //     * @param params - The parameters for the import operation.
//  //     * @param params.portableDid - The PortableDid object to import.
//  //     * @param params.keyManager - Optionally specify an external Key Management System (KMS) used to
//  //     *                            generate keys and sign data. If not given, a new
//  //     *                            {@link LocalKeyManager} instance will be created and
//  //     *                            used.
//  //     * @returns A Promise resolving to a `BearerDid` object representing the DID formed from the
//  //     *          provided PortableDid.
//  //     * @throws An error if the PortableDid document does not contain any verification methods, lacks
//  //     *         an Identity Key, or the keys for any verification method are missing in the key
//  //     *         manager.
//  //     */
//  //    public static async import({ portableDid, keyManager = new LocalKeyManager() }: {
//  //      keyManager?: CryptoApi & KeyImporterExporter<KmsImportKeyParams, KeyIdentifier, KmsExportKeyParams>;
//  //      portableDid: PortableDid;
//  //    }): Promise<BearerDid> {
//  //      // Verify the DID method is supported.
//  //      const parsedDid = Did.parse(portableDid.uri);
//  //      if (parsedDid?.method !== DidDht.methodName) {
//  //        throw new DidError(DidErrorCode.MethodNotSupported, `Method not supported`);
//  //      }

//  //      const did = await BearerDid.import({ portableDid, keyManager });

//  //      // Validate that the given verification methods contain an Identity Key.
//  //      if (!did.document.verificationMethod?.some(vm => vm.id?.split('#').pop() === '0')) {
//  //        throw new DidError(DidErrorCode.InvalidDidDocument, `DID document must contain an Identity Key`);
//  //      }

//  //      return did;
//  //    }

//  //    /**
//  //     * Given the W3C DID Document of a `did:dht` DID, return the verification method that will be used
//  //     * for signing messages and credentials. If given, the `methodId` parameter is used to select the
//  //     * verification method. If not given, the Identity Key's verification method with an ID fragment
//  //     * of '#0' is used.
//  //     *
//  //     * @param params - The parameters for the `getSigningMethod` operation.
//  //     * @param params.didDocument - DID Document to get the verification method from.
//  //     * @param params.methodId - ID of the verification method to use for signing.
//  //     * @returns Verification method to use for signing.
//  //     */
//  //    public static async getSigningMethod({ didDocument, methodId = '#0' }: {
//  //      didDocument: DidDocument;
//  //      methodId?: string;
//  //    }): Promise<DidVerificationMethod> {
//  //      // Verify the DID method is supported.
//  //      const parsedDid = Did.parse(didDocument.id);
//  //      if (parsedDid && parsedDid.method !== this.methodName) {
//  //        throw new DidError(DidErrorCode.MethodNotSupported, `Method not supported: ${parsedDid.method}`);
//  //      }

//  //      // Attempt to find a verification method that matches the given method ID, or if not given,
//  //      // find the first verification method intended for signing claims.
//  //      const verificationMethod = didDocument.verificationMethod?.find(
//  //        vm => extractDidFragment(vm.id) === (extractDidFragment(methodId) ?? extractDidFragment(didDocument.assertionMethod?.[0]))
//  //      );

//  //      if (!(verificationMethod && verificationMethod.publicKeyJwk)) {
//  //        throw new DidError(DidErrorCode.InternalError, 'A verification method intended for signing could not be determined from the DID Document');
//  //      }

//  //      return verificationMethod;
//  //    }

//  //    /**
//  //     * Publishes a DID to the DHT, making it publicly discoverable and resolvable.
//  //     *
//  //     * This method handles the publication of a DID Document associated with a `did:dht` DID to the
//  //     * Mainline DHT network. The publication process involves storing the DID Document in Mainline DHT
//  //     * via a Pkarr relay server.
//  //     *
//  //     * @remarks
//  //     * - This method is typically invoked automatically during the creation of a new DID unless the
//  //     *   `publish` option is set to `false`.
//  //     * - For existing, unpublished DIDs, it can be used to publish the DID Document to Mainline DHT.
//  //     * - The method relies on the specified Pkarr relay server to interface with the DHT network.
//  //     *
//  //     * @example
//  //     * ```ts
//  //     * // Generate a new DID and keys but explicitly disable publishing.
//  //     * const did = await DidDht.create({ options: { publish: false } });
//  //     * // Publish the DID to the DHT.
//  //     * const registrationResult = await DidDht.publish({ did });
//  //     * // `registrationResult.didDocumentMetadata.published` is true if the DID was successfully published.
//  //     * ```
//  //     *
//  //     * @param params - The parameters for the `publish` operation.
//  //     * @param params.did - The `BearerDid` object representing the DID to be published.
//  //     * @param params.gatewayUri - Optional. The URI of a server involved in executing DID method
//  //     *                            operations. In the context of publishing, the endpoint is expected
//  //     *                            to be a DID DHT Gateway or Pkarr Relay. If not specified, a default
//  //     *                            gateway node is used.
//  //     * @returns A promise that resolves to a {@link DidRegistrationResult} object that contains
//  //     *          the result of registering the DID with a DID DHT Gateway or Pkarr relay.
//  //     */
//  //blic static async publish({ did, gatewayUri = DEFAULT_GATEWAY_URI }: {
//  //did: BearerDid;
//  //gatewayUri?: string;

//  //: Promise<DidRegistrationResult> {
//  //const registrationResult = await DidDhtDocument.put({ did, gatewayUri });

//  //return registrationResult;


//  //    /**
//  //     * Resolves a `did:dht` identifier to its corresponding DID document.
//  //     *
//  //     * This method performs the resolution of a `did:dht` DID, retrieving its DID Document from the
//  //     * Mainline DHT network. The process involves querying the DHT network via a Pkarr relay server to
//  //     * retrieve the DID Document that corresponds to the given DID identifier.
//  //     *
//  //     * @remarks
//  //     * - If a `gatewayUri` option is not specified, a default Pkarr relay is used to access the DHT
//  //     *   network.
//  //     * - It decodes the DID identifier and retrieves the associated DID Document and metadata.
//  //     * - In case of resolution failure, appropriate error information is returned.
//  //     *
//  //     * @example
//  //     * ```ts
//  //     * const resolutionResult = await DidDht.resolve('did:dht:example');
//  //     * ```
//  //     *
//  //     * @param didUri - The DID to be resolved.
//  //     * @param options - Optional parameters for resolving the DID. Unused by this DID method.
//  //     * @returns A Promise resolving to a {@link DidResolutionResult} object representing the result of
//  //     *          the resolution.
//  //     */
//  //    public static async resolve(didUri: string, options: DidResolutionOptions = {}): Promise<DidResolutionResult> {
//  //      // To execute the read method operation, use the given gateway URI or a default.
//  //      const gatewayUri = options?.gatewayUri ?? DEFAULT_GATEWAY_URI;

//  //      try {
//  //        // Attempt to decode the z-base-32-encoded identifier.
//  //        await DidDhtUtils.identifierToIdentityKey({ didUri });

//  //        // Attempt to retrieve the DID document and metadata from the DHT network.
//  //        const { didDocument, didDocumentMetadata } = await DidDhtDocument.get({ didUri, gatewayUri });

//  //        // If the DID document was retrieved successfully, return it.
//  //        return {
//  //          ...EMPTY_DID_RESOLUTION_RESULT,
//  //          didDocument,
//  //          didDocumentMetadata
//  //        };

//  //      } catch (error: any) {
//  //        // Rethrow any unexpected errors that are not a `DidError`.
//  //        if (!(error instanceof DidError)) throw new Error(error);

//  //        // Return a DID Resolution Result with the appropriate error code.
//  //        return {
//  //          ...EMPTY_DID_RESOLUTION_RESULT,
//  //          didResolutionMetadata: {
//  //            error: error.code,
//  //            ...error.message && { errorMessage: error.message }
//  //          }
//  //        };
//  //      }
//  //    }
//  //  }

//  //  /**
//  //   * The `DidDhtDocument` class provides functionality for interacting with the DID document stored in
//  //   * Mainline DHT in support of DID DHT method create, resolve, update, and deactivate operations.
//  //   *
//  //   * This class includes methods for retrieving and publishing DID documents to and from the DHT,
//  //   * using DNS packet encoding and DID DHT Gateway or Pkarr Relay servers.
//  //   */
//  //  export class DidDhtDocument {
//  //    /**
//  //     * Retrieves a DID document and its metadata from the DHT network.
//  //     *
//  //     * @param params - The parameters for the get operation.
//  //     * @param params.didUri - The DID URI containing the Identity Key.
//  //     * @param params.gatewayUri - The DID DHT Gateway or Pkarr Relay URI.
//  //     * @returns A Promise resolving to a {@link DidResolutionResult} object containing the DID
//  //     *          document and its metadata.
//  //     */
//  //    public static async get({ didUri, gatewayUri }: {
//  //      didUri: string;
//  //      gatewayUri: string;
//  //    }): Promise<DidResolutionResult> {
//  //      // Decode the z-base-32 DID identifier to public key as a byte array.
//  //      const publicKeyBytes = DidDhtUtils.identifierToIdentityKeyBytes({ didUri });

//  //      // Retrieve the signed BEP44 message from a DID DHT Gateway or Pkarr relay.
//  //      const bep44Message = await DidDhtDocument.pkarrGet({ gatewayUri, publicKeyBytes });

//  //      // Verify the signature of the BEP44 message and parse the value to a DNS packet.
//  //      const dnsPacket = await DidDhtUtils.parseBep44GetMessage({ bep44Message });

//  //      // Convert the DNS packet to a DID document and metadata.
//  //      const resolutionResult = await DidDhtDocument.fromDnsPacket({ didUri, dnsPacket });

//  //      // Set the version ID of the DID document metadata to the sequence number of the BEP44 message.
//  //      resolutionResult.didDocumentMetadata.versionId = bep44Message.seq.toString();

//  //      return resolutionResult;
//  //    }

//  //    /**
//  //     * Publishes a DID document to the DHT network.
//  //     *
//  //     * @param params - The parameters to use when publishing the DID document to the DHT network.
//  //     * @param params.did - The DID object whose DID document will be published.
//  //     * @param params.gatewayUri - The DID DHT Gateway or Pkarr Relay URI.
//  //     * @returns A promise that resolves to a {@link DidRegistrationResult} object that contains
//  //     *          the result of registering the DID with a DID DHT Gateway or Pkarr relay.
//  //     */


//  //    /**
//  //     * Retrieves a signed BEP44 message from a DID DHT Gateway or Pkarr Relay server.
//  //     *
//  //     * @see {@link https://github.com/Nuhvi/pkarr/blob/main/design/relays.md | Pkarr Relay design}
//  //     *
//  //     * @param params
//  //     * @param params.gatewayUri - The DID DHT Gateway or Pkarr Relay URI.
//  //     * @param params.publicKeyBytes - The public key bytes of the Identity Key, z-base-32 encoded.
//  //     * @returns A promise resolving to a BEP44 message containing the signed DNS packet.
//  //    */
//  //    private static async pkarrGet({ gatewayUri, publicKeyBytes }: {
//  //      publicKeyBytes: Uint8Array;
//  //      gatewayUri: string;
//  //    }): Promise<Bep44Message> {
//  //      // The identifier (key in the DHT) is the z-base-32 encoding of the Identity Key.
//  //      const identifier = Convert.uint8Array(publicKeyBytes).toBase32Z();

//  //      // Concatenate the gateway URI with the identifier to form the full URL.
//  //      const url = new URL(identifier, gatewayUri).href;

//  //      // Transmit the Get request to the DID DHT Gateway or Pkarr Relay and get the response.
//  //      let response: Response;
//  //      try {
//  //        response = await fetch(url, { method: 'GET' });

//  //        if (!response.ok) {
//  //          throw new DidError(DidErrorCode.NotFound, `Pkarr record not found for: ${identifier}`);
//  //        }

//  //      } catch (error: any) {
//  //        if (error instanceof DidError) throw error;
//  //        throw new DidError(DidErrorCode.InternalError, `Failed to fetch Pkarr record: ${error.message}`);
//  //      }

//  //      // Read the Fetch Response stream into a byte array.
//  //      const messageBytes = await response.arrayBuffer();

//  //      if(!messageBytes) {
//  //        throw new DidError(DidErrorCode.NotFound, `Pkarr record not found for: ${identifier}`);
//  //      }

//  //      if (messageBytes.byteLength < 72) {
//  //        throw new DidError(DidErrorCode.InvalidDidDocumentLength, `Pkarr response must be at least 72 bytes but got: ${messageBytes.byteLength}`);
//  //      }

//  //      if (messageBytes.byteLength > 1072) {
//  //        throw new DidError(DidErrorCode.InvalidDidDocumentLength, `Pkarr response exceeds 1000 byte limit: ${messageBytes.byteLength}`);
//  //      }

//  //      // Decode the BEP44 message from the byte array.
//  //      const bep44Message: Bep44Message = {
//  //        k   : publicKeyBytes,
//  //        seq : Number(new DataView(messageBytes).getBigUint64(64)),
//  //        sig : new Uint8Array(messageBytes, 0, 64),
//  //        v   : new Uint8Array(messageBytes, 72)
//  //      };

//  //      return bep44Message;
//  //    }

//  //    /**
//  //     * Publishes a signed BEP44 message to a DID DHT Gateway or Pkarr Relay server.
//  //     *
//  //     * @see {@link https://github.com/Nuhvi/pkarr/blob/main/design/relays.md | Pkarr Relay design}
//  //     *
//  //     * @param params - The parameters to use when publishing a signed BEP44 message to a Pkarr relay server.
//  //     * @param params.gatewayUri - The DID DHT Gateway or Pkarr Relay URI.
//  //     * @param params.bep44Message - The BEP44 message to be published, containing the signed DNS packet.
//  //     * @returns A promise resolving to `true` if the message was successfully published, otherwise `false`.
//  //     */
//  //ivate static async pkarrPut({ gatewayUri, bep44Message }: {
//  //bep44Message: Bep44Message;
//  //gatewayUri: string;
//  //: Promise<boolean> {
//  //// The identifier (key in the DHT) is the z-base-32 encoding of the Identity Key.
//  //const identifier = Convert.uint8Array(bep44Message.k).toBase32Z();

//  //// Concatenate the gateway URI with the identifier to form the full URL.
//  //const url = new URL(identifier, gatewayUri).href;

//  //// Construct the body of the request according to the Pkarr relay specification.
//  //const body = new Uint8Array(bep44Message.v.length + 72);
//  //body.set(bep44Message.sig, 0);
//  //new DataView(body.buffer).setBigUint64(bep44Message.sig.length, BigInt(bep44Message.seq));
//  //body.set(bep44Message.v, bep44Message.sig.length + 8);

//  //// Transmit the Put request to the Pkarr relay and get the response.
//  //let response: Response;
//  //try {
//  //  response = await fetch(url, {
//  //    method  : 'PUT',
//  //    headers : { 'Content-Type': 'application/octet-stream' },
//  //    body
//  //  });

//  //} catch (error: any) {
//  //  throw new DidError(DidErrorCode.InternalError, `Failed to put Pkarr record for identifier ${identifier}: ${error.message}`);
//  //}

//  //// Return `true` if the DHT request was successful, otherwise return `false`.
//  //return response.ok;


//  //    /**
//  //     * Converts a DNS packet to a DID document according to the DID DHT specification.
//  //     *
//  //     * @see {@link https://did-dht.com/#dids-as-dns-records | DID DHT Specification, § DIDs as DNS Records}
//  //     *
//  //     * @param params - The parameters to use when converting a DNS packet to a DID document.
//  //     * @param params.didUri - The DID URI of the DID document.
//  //     * @param params.dnsPacket - The DNS packet to convert to a DID document.
//  //     * @returns A Promise resolving to a {@link DidResolutionResult} object containing the DID
//  //     *          document and its metadata.
//  //     */
//  //    public static async fromDnsPacket({ didUri, dnsPacket }: {
//  //      didUri: string;
//  //      dnsPacket: Packet;
//  //    }): Promise<DidResolutionResult> {
//  //      // Begin constructing the DID Document.
//  //      const didDocument: DidDocument = { id: didUri };

//  //      // Since the DID document is being retrieved from the DHT, it is considered published.
//  //      const didDocumentMetadata: DidMetadata = {
//  //        published: true
//  //      };

//  //      const idLookup = new Map<string, string>();

//  //      for (const answer of dnsPacket?.answers ?? []) {
//  //        // DID DHT properties are ONLY present in DNS TXT records.
//  //        if (answer.type !== 'TXT') continue;

//  //        // Get the DID DHT record identifier (e.g., k0, aka, did, etc.) from the DNS resource name.
//  //        const dnsRecordId = answer.name.split('.')[0].substring(1);

//  //        switch (true) {
//  //          // Process an also known as record.
//  //          case dnsRecordId.startsWith('aka'): {
//  //            // Decode the DNS TXT record data value to a string.
//  //            const data = DidDhtUtils.parseTxtDataToString(answer.data);

//  //            // Add the 'alsoKnownAs' property to the DID document.
//  //            didDocument.alsoKnownAs = data.split(VALUE_SEPARATOR);

//  //            break;
//  //          }

//  //          // Process a controller record.
//  //          case dnsRecordId.startsWith('cnt'): {
//  //            // Decode the DNS TXT record data value to a string.
//  //            const data = DidDhtUtils.parseTxtDataToString(answer.data);

//  //            // Add the 'controller' property to the DID document.
//  //            didDocument.controller = data.includes(VALUE_SEPARATOR) ? data.split(VALUE_SEPARATOR) : data;

//  //            break;
//  //          }

//  //          // Process verification methods.
//  //          case dnsRecordId.startsWith('k'): {
//  //            // Get the method ID fragment (id), key type (t), Base64URL-encoded public key (k), and
//  //            // optionally, controller (c) from the decoded TXT record data.
//  //            const { id, t, k, c, a: parsedAlg } = DidDhtUtils.parseTxtDataToObject(answer.data);

//  //            // Convert the public key from Base64URL format to a byte array.
//  //            const publicKeyBytes = Convert.base64Url(k).toUint8Array();

//  //            // Use the key type integer to look up the cryptographic curve name.
//  //            const namedCurve = DidDhtRegisteredKeyType[Number(t)];

//  //            // Convert the public key from a byte array to JWK format.
//  //            let publicKey = await DidDhtUtils.keyConverter(namedCurve).bytesToPublicKey({ publicKeyBytes });

//  //            publicKey.alg = parsedAlg || KeyTypeToDefaultAlgorithmMap[Number(t) as DidDhtRegisteredKeyType];

//  //            // Determine the Key ID (kid): '0' for the identity key or JWK thumbprint for others.
//  //            publicKey.kid = dnsRecordId.endsWith('0') ? '0' : await computeJwkThumbprint({ jwk: publicKey });

//  //            // Initialize the `verificationMethod` array if it does not already exist.
//  //            didDocument.verificationMethod ??= [];

//  //            // Prepend the DID URI to the ID fragment to form the full verification method ID.
//  //            const methodId = `${didUri}#${id}`;

//  //            // Add the verification method to the DID document.
//  //            didDocument.verificationMethod.push({
//  //              id           : methodId,
//  //              type         : 'JsonWebKey',
//  //              controller   : c ?? didUri,
//  //              publicKeyJwk : publicKey,
//  //            });

//  //            // Add a mapping from the DNS record ID (e.g., 'k0', 'k1', etc.) to the verification
//  //            // method ID (e.g., 'did:dht:...#0', etc.).
//  //            idLookup.set(dnsRecordId, methodId);

//  //            break;
//  //          }

//  //          // Process services.
//  //          case dnsRecordId.startsWith('s'): {
//  //            // Get the service ID fragment (id), type (t), service endpoint (se), and optionally,
//  //            // other properties from the decoded TXT record data.
//  //            const { id, t, se, ...customProperties } = DidDhtUtils.parseTxtDataToObject(answer.data);

//  //            // The service endpoint can either be a string or an array of strings.
//  //            const serviceEndpoint = se.includes(VALUE_SEPARATOR) ? se.split(VALUE_SEPARATOR) : se;

//  //            // Convert custom property values to either a string or an array of strings.
//  //            const serviceProperties = Object.fromEntries(Object.entries(customProperties).map(
//  //              ([k, v]) => [k, v.includes(VALUE_SEPARATOR) ? v.split(VALUE_SEPARATOR) : v]
//  //            ));

//  //            // Initialize the `service` array if it does not already exist.
//  //            didDocument.service ??= [];

//  //            didDocument.service.push({
//  //              ...serviceProperties,
//  //              id   : `${didUri}#${id}`,
//  //              type : t,
//  //              serviceEndpoint
//  //            });

//  //            break;
//  //          }

//  //          // Process DID DHT types.
//  //          case dnsRecordId.startsWith('typ'): {
//  //            // Decode the DNS TXT record data value to an object.
//  //            const { id: types } = DidDhtUtils.parseTxtDataToObject(answer.data);

//  //            // Add the DID DHT Registered DID Types represented as numbers to DID metadata.
//  //            didDocumentMetadata.types = types.split(VALUE_SEPARATOR).map(typeInteger => Number(typeInteger));

//  //            break;
//  //          }

//  //          // Process root record.
//  //          case dnsRecordId.startsWith('did'): {
//  //            // Helper function that maps verification relationship values to verification method IDs.
//  //            const recordIdsToMethodIds = (data: string): string[] => data
//  //              .split(VALUE_SEPARATOR)
//  //              .map(dnsRecordId => idLookup.get(dnsRecordId))
//  //              .filter((id): id is string => typeof id === 'string');

//  //            // Decode the DNS TXT record data and destructure verification relationship properties.
//  //            const { auth, asm, del, inv, agm } = DidDhtUtils.parseTxtDataToObject(answer.data);

//  //            // Add the verification relationships, if any, to the DID document.
//  //            if (auth) didDocument.authentication = recordIdsToMethodIds(auth);
//  //            if (asm) didDocument.assertionMethod = recordIdsToMethodIds(asm);
//  //            if (del) didDocument.capabilityDelegation = recordIdsToMethodIds(del);
//  //            if (inv) didDocument.capabilityInvocation = recordIdsToMethodIds(inv);
//  //            if (agm) didDocument.keyAgreement = recordIdsToMethodIds(agm);

//  //            break;
//  //          }
//  //        }
//  //      }

//  //      return { didDocument, didDocumentMetadata, didResolutionMetadata: {} };
//  //    }

//  //    /**
//  //     * Converts a DID document to a DNS packet according to the DID DHT specification.
//  //     *
//  //     * @see {@link https://did-dht.com/#dids-as-dns-records | DID DHT Specification, § DIDs as DNS Records}
//  //     *
//  //     * @param params - The parameters to use when converting a DID document to a DNS packet.
//  //     * @param params.didDocument - The DID document to convert to a DNS packet.
//  //     * @param params.didMetadata - The DID metadata to include in the DNS packet.
//  //     * @param params.authoritativeGatewayUris - The URIs of the Authoritative Gateways to generate NS records from.
//  //     * @returns A promise that resolves to a DNS packet.
//  //     */


//  //    /**
//  //     * Gets the unique portion of the DID identifier after the last `:` character.
//  //     * e.g. `did:dht:example` -> `example`
//  //     *
//  //     * @param did - The DID to extract the unique suffix from.
//  //     */
//  //    private static getUniqueDidSuffix(did: string ): string {
//  //      return did.split(':')[2];
//  //    }
//  //  }

//  //  /**
//  //   * The `DidDhtUtils` class provides utility functions to support operations in the DID DHT method.
//  //   * This includes functions for creating and parsing BEP44 messages, handling identity keys, and
//  //   * converting between different formats and representations.
//  //   */
//  //  export class DidDhtUtils {
//  //    /**
//  //     * Creates a BEP44 put message, which is used to publish a DID document to the DHT network.
//  //     *
//  //     * @param params - The parameters to use when creating the BEP44 put message
//  //     * @param params.dnsPacket - The DNS packet to encode in the BEP44 message.
//  //     * @param params.publicKeyBytes - The public key bytes of the Identity Key.
//  //     * @param params.signer - Signer that can sign and verify data using the Identity Key.
//  //     * @returns A promise that resolves to a BEP44 put message.
//  //     */
//  //    public static async createBep44PutMessage({ dnsPacket, publicKeyBytes, signer }: {
//  //        dnsPacket: Packet;
//  //        publicKeyBytes: Uint8Array;
//  //        signer: Signer;
//  //      }): Promise<Bep44Message> {
//  //      // BEP44 requires that the sequence number be a monotoically increasing integer, so we use the
//  //      // current time in seconds since Unix epoch as a simple solution. Higher precision is not
//  //      // recommended since DID DHT documents are not expected to change frequently and there are
//  //      // small differences in system clocks that can cause issues if multiple clients are publishing
//  //      // updates to the same DID document.
//  //      const sequenceNumber = Math.ceil(Date.now() / 1000);

//  //      // Encode the DNS packet into a byte array containing a UDP payload.
//  //      const encodedDnsPacket = dnsPacketEncode(dnsPacket);

//  //      // Encode the sequence and DNS byte array to bencode format.
//  //      const bencodedData = bencode.encode({ seq: sequenceNumber, v: encodedDnsPacket }).subarray(1, -1);

//  //      if (bencodedData.length > 1000) {
//  //        throw new DidError(DidErrorCode.InvalidDidDocumentLength, `DNS packet exceeds the 1000 byte maximum size: ${bencodedData.length} bytes`);
//  //      }

//  //      // Sign the BEP44 message.
//  //      const signature = await signer.sign({ data: bencodedData });

//  //      return { k: publicKeyBytes, seq: sequenceNumber, sig: signature, v: encodedDnsPacket };
//  //    }

//  //    /**
//  //     * Converts a DID URI to a JSON Web Key (JWK) representing the Identity Key.
//  //     *
//  //     * @param params - The parameters to use for the conversion.
//  //     * @param params.didUri - The DID URI containing the Identity Key.
//  //     * @returns A promise that resolves to a JWK representing the Identity Key.
//  //     */
//  //    /**
//  //     * Returns the appropriate key converter for the specified cryptographic curve.
//  //     *
//  //     * @param curve - The cryptographic curve to use for the key conversion.
//  //     * @returns An `AsymmetricKeyConverter` for the specified curve.
//  //     */
//  //    public static keyConverter(curve: string): AsymmetricKeyConverter {
//  //      const converters: Record<string, AsymmetricKeyConverter> = {
//  //        'Ed25519' : Ed25519,
//  //        'P-256'   : {
//  //          // Wrap the key converter which produces uncompressed public key bytes to produce compressed key bytes as required by the DID DHT spec.
//  //          // See https://did-dht.com/#representing-keys for more info.
//  //          publicKeyToBytes: async ({ publicKey }: { publicKey: Jwk }): Promise<Uint8Array> => {
//  //            const publicKeyBytes = await Secp256r1.publicKeyToBytes({ publicKey });
//  //            const compressedPublicKey = await Secp256r1.compressPublicKey({ publicKeyBytes });
//  //            return compressedPublicKey;
//  //          },
//  //          bytesToPublicKey  : Secp256r1.bytesToPublicKey,
//  //          privateKeyToBytes : Secp256r1.privateKeyToBytes,
//  //          bytesToPrivateKey : Secp256r1.bytesToPrivateKey,
//  //        },
//  //        'secp256k1': {
//  //          // Wrap the key converter which produces uncompressed public key bytes to produce compressed key bytes as required by the DID DHT spec.
//  //          // See https://did-dht.com/#representing-keys for more info.
//  //          publicKeyToBytes: async ({ publicKey }: { publicKey: Jwk }): Promise<Uint8Array> => {
//  //            const publicKeyBytes = await Secp256k1.publicKeyToBytes({ publicKey });
//  //            const compressedPublicKey = await Secp256k1.compressPublicKey({ publicKeyBytes });
//  //            return compressedPublicKey;
//  //          },
//  //          bytesToPublicKey  : Secp256k1.bytesToPublicKey,
//  //          privateKeyToBytes : Secp256k1.privateKeyToBytes,
//  //          bytesToPrivateKey : Secp256k1.bytesToPrivateKey,
//  //        }
//  //      };

//  //      const converter = converters[curve];

//  //      if (!converter) throw new DidError(DidErrorCode.InvalidPublicKeyType, `Unsupported curve: ${curve}`);

//  //      return converter;
//  //    }

//  //    /**
//  //     * Parses and verifies a BEP44 Get message, converting it to a DNS packet.
//  //     *
//  //     * @param params - The parameters to use when verifying and parsing the BEP44 Get response message.
//  //     * @param params.bep44Message - The BEP44 message to verify and parse.
//  //     * @returns A promise that resolves to a DNS packet.
//  //     */
//  //    public static async parseBep44GetMessage({ bep44Message }: {
//  //      bep44Message: Bep44Message;
//  //    }): Promise<Packet> {
//  //      // Convert the public key byte array to JWK format.
//  //      const publicKey = await Ed25519.bytesToPublicKey({ publicKeyBytes: bep44Message.k });

//  //      // Encode the sequence and DNS byte array to bencode format.
//  //      const bencodedData = bencode.encode({ seq: bep44Message.seq, v: bep44Message.v }).subarray(1, -1);

//  //      // Verify the signature of the BEP44 message.
//  //      const isValid = await Ed25519.verify({
//  //        key       : publicKey,
//  //        signature : bep44Message.sig,
//  //        data      : bencodedData
//  //      });

//  //      if (!isValid) {
//  //        throw new DidError(DidErrorCode.InvalidSignature, `Invalid signature for DHT BEP44 message`);
//  //      }

//  //      return dnsPacketDecode(bep44Message.v);
//  //    }

//  //    /**
//  //     * Decodes and parses the data value of a DNS TXT record into a key-value object.
//  //     *
//  //     * @param txtData - The data value of a DNS TXT record.
//  //     * @returns An object containing the key/value pairs of the TXT record data.
//  //     */
//  //    public static parseTxtDataToObject(txtData: TxtData): Record<string, string> {
//  //      return this.parseTxtDataToString(txtData).split(PROPERTY_SEPARATOR).reduce((acc, pair) => {
//  //        const [key, value] = pair.split('=');
//  //        acc[key] = value;
//  //        return acc;
//  //      }, {} as Record<string, string>);
//  //    }

//  //    /**
//  //     * Decodes and parses the data value of a DNS TXT record into a string.
//  //     *
//  //     * @param txtData - The data value of a DNS TXT record.
//  //     * @returns A string representation of the TXT record data.
//  //     */
//  //    public static parseTxtDataToString(txtData: TxtData): string {
//  //      if (typeof txtData === 'string') {
//  //        return txtData;
//  //      } else if (txtData instanceof Uint8Array) {
//  //        return Convert.uint8Array(txtData).toString();
//  //      } else if (Array.isArray(txtData)) {
//  //        return txtData.map(item => this.parseTxtDataToString(item)).join('');
//  //      } else {
//  //        throw new DidError(DidErrorCode.InternalError, 'Pkarr returned DNS TXT record with invalid data type');
//  //      }
//  //    }
//  //  }
