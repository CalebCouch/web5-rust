import type { DidMethodResolver } from '../methods/did-method.js';
import type { DidResolver, DidResolverCache, DidUrlDereferencer } from '../types/did-resolution.js';
import type { DidDereferencingOptions, DidDereferencingResult, DidResolutionOptions, DidResolutionResult, DidResource } from '../types/did-core.js';

import { Did } from '../did.js';
import { DidErrorCode } from '../did-error.js';
import { DidResolverCacheNoop } from './resolver-cache-noop.js';
import { EMPTY_DID_RESOLUTION_RESULT } from '../types/did-resolution.js';

pub struct UniversalResolver implements DidResolver, DidUrlDereferencer {
    cache: DidResolverCache,
    did_resolvers: HashMap<String, DidMethodResolver>,
}

impl<C: KeyValueStore<String, DidResolutionResult>> UniversalResolver {
    pub fn new(cache: Option<C>, did_resolvers: Vec<DidResolver>) -> Self {
        let cache = cache.unwrap_or(DidResolverCacheNoop::new());
        let map: HashMap<String, DidMethodResolver> = HashMap::new();
        for resolver in did_resolvers {
            map.insert(resolver.method_name, resolver);
        }
        UniversalResolver{cache, did_resolvers: map}
    }
}

impl DidResolver for UniversalResolver {
    async fn resolve(&self, did_uri: String, options: Option<DidResolutionOptions>): Result<DidResolutionResult, Error> {
        let parsed_did = Did::parse(did_uri).ok_or(Error::InvalidDid(did_uri))?;

        let resolver = self.did_resolvers.get(parsedDid.method).ok_or(Error::MethodNotSupported(parsedDid.method))?;

        if let Some(cached_resolution_result) = self.cache.get(parsedDid.uri).await? {
            return Ok(cached_resolution_result);
        } else {
            resolver.resolve(parsedDid.uri, 

        }

    if (cachedResolutionResult) {
      return cachedResolutionResult;
    } else {
      const resolutionResult = await resolver.resolve(parsedDid.uri, options);
      if (!resolutionResult.didResolutionMetadata.error) {
        // Cache the resolution result if it was successful.
        await this.cache.set(parsedDid.uri, resolutionResult);
      }

      return resolutionResult;
    }
  }
}

  /**
   * Resolves a DID to a DID Resolution Result.
   *
   * If the DID Resolution Result is present in the cache, it returns the cached result. Otherwise,
   * it uses the appropriate method resolver to resolve the DID, stores the resolution result in the
   * cache, and returns the resolultion result.
   *
   * @param didUri - The DID or DID URL to resolve.
   * @returns A promise that resolves to the DID Resolution Result.
   */
  public async resolve(didUri: string, options?: DidResolutionOptions): Promise<DidResolutionResult> {

    const parsedDid = Did.parse(didUri);
    if (!parsedDid) {
      return {
        ...EMPTY_DID_RESOLUTION_RESULT,
        didResolutionMetadata: {
          error        : DidErrorCode.InvalidDid,
          errorMessage : `Invalid DID URI: ${didUri}`
        }
      };
    }

    const resolver = this.didResolvers.get(parsedDid.method);
    if (!resolver) {
      return {
        ...EMPTY_DID_RESOLUTION_RESULT,
        didResolutionMetadata: {
          error        : DidErrorCode.MethodNotSupported,
          errorMessage : `Method not supported: ${parsedDid.method}`
        }
      };
    }

    const cachedResolutionResult = await this.cache.get(parsedDid.uri);

    if (cachedResolutionResult) {
      return cachedResolutionResult;
    } else {
      const resolutionResult = await resolver.resolve(parsedDid.uri, options);
      if (!resolutionResult.didResolutionMetadata.error) {
        // Cache the resolution result if it was successful.
        await this.cache.set(parsedDid.uri, resolutionResult);
      }

      return resolutionResult;
    }
  }

  /**
   * Dereferences a DID (Decentralized Identifier) URL to a corresponding DID resource.
   *
   * This method interprets the DID URL's components, which include the DID method, method-specific
   * identifier, path, query, and fragment, and retrieves the related resource as per the DID Core
   * specifications.
   *
   * The dereferencing process involves resolving the DID contained in the DID URL to a DID document,
   * and then extracting the specific part of the document identified by the fragment in the DID URL.
   * If no fragment is specified, the entire DID document is returned.
   *
   * This method supports resolution of different components within a DID document such as service
   * endpoints and verification methods, based on their IDs. It accommodates both full and
   * DID URLs as specified in the DID Core specification.
   *
   * More information on DID URL dereferencing can be found in the
   * {@link https://www.w3.org/TR/did-core/#did-url-dereferencing | DID Core specification}.
   *
   * TODO: This is a partial implementation and does not fully implement DID URL dereferencing. (https://github.com/TBD54566975/web5-js/issues/387)
   *
   * @param didUrl - The DID URL string to dereference.
   * @param [_options] - Input options to the dereference function. Optional.
   * @returns a {@link DidDereferencingResult}
   */
  async dereference(
    didUrl: string,
    _options?: DidDereferencingOptions
  ): Promise<DidDereferencingResult> {

    // Validate the given `didUrl` confirms to the DID URL syntax.
    const parsedDidUrl = Did.parse(didUrl);

    if (!parsedDidUrl) {
      return {
        dereferencingMetadata : { error: DidErrorCode.InvalidDidUrl },
        contentStream         : null,
        contentMetadata       : {}
      };
    }

    // Obtain the DID document for the input DID by executing DID resolution.
    const { didDocument, didResolutionMetadata, didDocumentMetadata } = await this.resolve(parsedDidUrl.uri);

    if (!didDocument) {
      return {
        dereferencingMetadata : { error: didResolutionMetadata.error },
        contentStream         : null,
        contentMetadata       : {}
      };
    }

    // Return the entire DID Document if no query or fragment is present on the DID URL.
    if (!parsedDidUrl.fragment || parsedDidUrl.query) {
      return {
        dereferencingMetadata : { contentType: 'application/did+json' },
        contentStream         : didDocument,
        contentMetadata       : didDocumentMetadata
      };
    }

    const { service = [], verificationMethod = [] } = didDocument;

    // Create a set of possible id matches. The DID spec allows for an id to be the entire
    // did#fragment or just #fragment.
    // @see {@link }https://www.w3.org/TR/did-core/#relative-did-urls | Section 3.2.2, Relative DID URLs}.
    // Using a Set for fast string comparison since some DID methods have long identifiers.
    const idSet = new Set([didUrl, parsedDidUrl.fragment, `#${parsedDidUrl.fragment}`]);

    let didResource: DidResource | undefined;

    // Find the first matching verification method in the DID document.
    for (let vm of verificationMethod) {
      if (idSet.has(vm.id)) {
        didResource = vm;
        break;
      }
    }

    // Find the first matching service in the DID document.
    for (let svc of service) {
      if (idSet.has(svc.id)) {
        didResource = svc;
        break;
      }
    }

    if (didResource) {
      return {
        dereferencingMetadata : { contentType: 'application/did+json' },
        contentStream         : didResource,
        contentMetadata       : didResolutionMetadata
      };
    } else {
      return {
        dereferencingMetadata : { error: DidErrorCode.NotFound },
        contentStream         : null,
        contentMetadata       : {},
      };
    }
  }
}
