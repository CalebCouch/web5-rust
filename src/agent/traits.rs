use super::Error;

use super::structs::{Header, Task};
use super::compiler::{CompilerMemory, CompilerCache};

use std::any::Any;

use dyn_clone::{clone_trait_object, DynClone};
use downcast_rs::DowncastSync;
use simple_crypto::Hashable;
use serde::Serialize;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait Command: TypeDebug + std::fmt::Debug + Send + Sync + DynClone + erased_serde::Serialize {
    async fn process<'a>(
        self: Box<Self>, uuid: Uuid, header: Header,
        memory: &mut CompilerMemory<'a>, cache: &mut CompilerCache
    ) -> Result<Vec<(Uuid, Task)>, Error>;

    fn serialize(&self) -> String {
        let mut buffer = std::io::BufWriter::new(Vec::<u8>::new());
        let serializer = &mut serde_json::ser::Serializer::new(&mut buffer);
        self.erased_serialize(&mut Box::new(<dyn erased_serde::Serializer>::erase(
            serializer
        ))).unwrap();
        format!(
            "{}::{}",
            (*self).get_full_type(),
            std::str::from_utf8(&buffer.into_inner().unwrap()).unwrap()
        )
    }
}
clone_trait_object!(Command);
erased_serde::serialize_trait_object!(Command);

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

pub trait Response: Any + erased_serde::Serialize + std::fmt::Debug + DowncastSync + DynClone + TypeDebug {
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
erased_serde::serialize_trait_object!(Response);
clone_trait_object!(Response);


impl<T: Any + std::fmt::Debug + Clone + Sync + Send + TypeDebug + Serialize> Response for T {}
downcast_rs::impl_downcast!(sync Response);
