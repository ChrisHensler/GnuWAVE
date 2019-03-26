mod Service;

use crate::Service::SDS::TraitSecureDataService;

//If you try to include the line below, you get a compilation error proving that the trait is private therefore all the methods are private within it asewell.
//use crate::Service::PrivateSDS;
use std::io;
fn main() {
  let (SDS,SSME) = Service::Initialize();
  println!("Compiled ok {}", SDS.getString());
  //println!("The secret is {}", SSME.Secret());
}
