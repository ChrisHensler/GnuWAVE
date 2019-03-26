pub mod SDS;


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


//Now implement SDServices for SSME
impl SDS::TraitSecureDataService for SSME {
  fn getString(&self) -> String {
    String::from("Wrong Services package!")
  }
  fn Secret(&self) -> String {
    println!("Well shit, you're about to print nothing");
    String::from("nothing")
  }
}

//Create the structs
pub fn Initialize() -> (SDS::SDS,SSME) {
  let  r=SDS::Initialize();
  let m= SSME {t:String::from("no"),};
  (r,m)
}
