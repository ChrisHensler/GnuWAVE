pub trait SDSServices {
  fn getString(&self) -> String;
  fn Secret(&self) -> String;
}
trait PrivateSDS {
  fn getSecret(&self) -> String;
}
pub struct SDS{
  s:String,
}
//Using the commented out method below does not require
//Useage of the crate::Service::SDSService but does not
//Allow for inheritance.
/*impl SDS {
  pub fn getString(&self) -> String {
    String::from("Greetings!")
  }
}*/
impl SDSServices for SDS {
  fn getString(&self) -> String {
    String::from("Greetings!")
  }
  fn Secret(&self) -> String {
    self.getSecret()
  }
}
impl PrivateSDS for SDS {
  fn getSecret(&self) -> String {
    String::from("It's a Secret")
  }
}
pub fn Initialize() -> SDS {
  SDS {
    s: String::from("Hello there!"),
    }
}
