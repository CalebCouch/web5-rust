use super::Error;

use super::structs::{Header, Task};
use super::compiler::{CompilerMemory, CompilerCache};

use crate::dids::{DidResolver, Endpoint, Did};

use std::any::Any;

use dyn_clone::{clone_trait_object, DynClone};
use downcast_rs::DowncastSync;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait Command<'a>: TypeDebug + std::fmt::Debug + Send + Sync + DynClone {
    async fn process(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, cache: &mut CompilerCache
    ) -> Result<Vec<(Uuid, Task<'a>)>, Error>;

    async fn get_endpoints(
        &self, dids: Vec<Did>, did_resolver: &dyn DidResolver
    ) -> Result<Vec<Endpoint>, Error> {
        let endpoints = did_resolver.get_endpoints(&dids).await?;
        if endpoints.is_empty() {panic!("Did set had no endpoints");}
        Ok(endpoints)
    }
}
clone_trait_object!(for<'a> Command<'a>);

pub trait TypeDebug: std::fmt::Debug {
    fn get_full_type(&self) -> String {
        std::any::type_name_of_val(self).to_string()
    }
    fn get_type(&self) -> String {
        let full_type = self.get_full_type();
        let split = full_type.split("::").collect::<Vec<_>>();
        split[split.len()-1].to_string().replace(">", "").replace("<", "")
    }

    fn debug(&self, len: usize) -> String {
        format!("{}::{}", self.get_type(), self.truncate_debug(len))
    }

    fn truncate_debug(&self, len: usize) -> String {
        let debug = format!("{:?}", self);
        if debug.len() > len {debug[..len].to_string()} else {debug}
    }
}

impl<T: std::fmt::Debug> TypeDebug for T {}

pub trait Response: Any + std::fmt::Debug + DowncastSync + DynClone + TypeDebug {
  //pub fn handle_error(self) -> Result<Box<dyn Response>, Error> {
  //    if let Some(error) = response.downcast_ref::<ErrorWrapper>() {
  //        return error.into();
  //    } else {Ok(self)}
  //}
  //pub fn unique_read_private(self) -> Result<(), Error> {
  //    for response in self.downcast::<Vec<Box<dyn Response>>>()? {
  //        response.downcast::<Vec<PrivateRecord>>()?;
  //    }
  //    Ok(())
  //}

  //fn empty_success(self: Box<Self>) -> Result<(), Error> where Self: Sized + DowncastSync {
  //    for response in self.downcast::<Vec<Box<dyn Response>>>()? {
  //        response.downcast::<()>()?;
  //    }
  //    Ok(())
  //}
}
clone_trait_object!(Response);


impl<T: Any + std::fmt::Debug + Clone + Sync + Send + TypeDebug> Response for T {}
downcast_rs::impl_downcast!(sync Response);
