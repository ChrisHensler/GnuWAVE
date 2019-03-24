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
pub struct SSME{
  t:String,
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
//Now implement SDServices for SSME
impl SDSServices for SSME {
  fn getString(&self) -> String {
    String::from("Wrong Services package!")
  }
  fn Secret(&self) -> String {
    println!("Well shit, you're about to print nothing");
    String::from("nothing")
  }
}
//Creat the structs
pub fn Initialize() -> (SDS,SSME) {
  let  r=SDS {
    s: String::from("Hello there!"),
    };
  let m= SSME {t:String::from("no"),};
  (r,m)
}
