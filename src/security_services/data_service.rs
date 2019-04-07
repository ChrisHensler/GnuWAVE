use super::access_points::TraitSecureDataService;
use super::super::Traits;
pub struct SecureDataService {
  s:String,
}
trait PrivateSDS {
  fn get_secret(&self) -> String;
}
impl Traits::Tester for SecureDataService {
  fn getme(&self) -> String{
    String::from("HE")
  }
}
impl TraitSecureDataService for SecureDataService {
  fn get_string(&self) -> String {
    String::from("Greetings!")
  }
  fn secret(&self) -> String {
    self.get_secret()
  }
}

impl PrivateSDS for SecureDataService {
  fn get_secret(&self) -> String {
    String::from("It's a Secret")
  }
}


pub fn new() -> (SecureDataService) {
  SecureDataService {
    s: String::from("Hello there!"),
  }
}
