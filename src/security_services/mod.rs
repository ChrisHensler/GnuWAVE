pub mod data_service;
pub mod access_points;
pub mod management_entity;

//Using the commented out method below does not require
//Useage of the crate::Service::SDSService but does not
//Allow for inheritance.
/*impl SDS {
  pub fn getString(&self) -> String {
    String::from("Greetings!")
  }
}*/

//Create the structs
pub fn initialize() -> (data_service::SecureDataService,management_entity::StationSecurityManagementEntity) {
  let r=data_service::new();
  let m=management_entity::new();
  (r,m)
}
