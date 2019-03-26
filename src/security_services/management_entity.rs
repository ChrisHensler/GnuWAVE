
use super::access_points;

pub struct StationSecurityManagementEntity {
  t:String,
}

//Now implement SDServices for SSME
impl access_points::TraitSecureDataService for StationSecurityManagementEntity {
  fn get_string(&self) -> String {
    String::from("Wrong Services package!")
  }
  fn secret(&self) -> String {
    println!("Well shit, you're about to print nothing");
    String::from("nothing")
  }
}

pub fn new() -> (StationSecurityManagementEntity) {
  StationSecurityManagementEntity {
    t: String::from("Hello there!"),
  }
}