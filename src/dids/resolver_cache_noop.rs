use crate::common::types::KeyValueStore;
use crate::common::error::Error as CommonError;
//use super::did_resolution::DidResolverCache;
use super::did_core::DidResolutionResult;

pub struct DidResolverCacheNoop {

}

//TODO DidResolverCache
impl KeyValueStore<String, DidResolutionResult> for DidResolverCacheNoop {
    async fn clear(&mut self) -> Result<(), CommonError> {
        Ok(())
    }
    async fn close(&mut self) -> Result<(), CommonError> {
        Ok(())
    }
    async fn delete(&mut self, _key: String) -> Result<bool, CommonError> {
        Ok(true)
    }
    async fn get(&mut self, _key: String) -> Result<Option<DidResolutionResult>, CommonError> {
        Ok(None)
    }
    async fn set(&mut self, _key: String, _value: DidResolutionResult) -> Result<(), CommonError> {
        Ok(())
    }
}
