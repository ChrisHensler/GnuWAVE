mod security_services;

use crate::security_services::access_points::TraitSecureDataService;

//If you try to include the line below, you get a compilation error proving that the trait is private therefore all the methods are private within it asewell.
//use crate::Service::PrivateSDS;
use std::io;

fn main() {
  let (sds,ssme) = security_services::initialize();
  println!("Compiled ok {}", sds.get_string());
  println!("Compiled ok {}", ssme.get_string());
  //println!("The secret is {}", SSME.Secret());
}
