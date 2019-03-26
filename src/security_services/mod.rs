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

#[cfg(test)]
mod tests {
  use super::data_service;
  use super::management_entity;
  use crate::security_services::access_points::TraitSecureDataService;

  #[test]
  fn test_ctors() {
    assert!(data_service::new().get_string() == "Greetings!");
    assert!(management_entity::new().get_string() == "Wrong Services package!");
  }

  #[test]
  #[should_panic]
  fn test_panic() {
    let a = 0;
    let b = 1/a;
  }

  #[test]
  #[should_panic(expected = "RUUUUUN!")]
  fn test_panic2() {
    panic!("RUUUUUN!");
  }
}