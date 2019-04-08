mod security_services;
mod Traits;
mod DataTypes;
use crate::DataTypes::*;
use crate::security_services::access_points::TraitSecureDataService;
use crate::Traits::Tester;
//If you try to include the line below, you get a compilation error proving that the trait is private therefore all the methods are private within it asewell.
//use crate::Service::PrivateSDS;
use std::io;

fn main() {
  let (sds,ssme) = security_services::initialize();
  println!("Compiled ok {}", sds.get_string());
  println!("Compiled ok {}", ssme.get_string());
  println!("{}",sds.getme());
  let s= ResultCode_SecSignedDataVerification::SPDULocalConsistency(SPDULocalConsistency::PSIDsDontMatch);
  match s {
    ResultCode_SecSignedDataVerification::SPDUParsing(sub) => println!("yay"),  
    ResultCode_SecSignedDataVerification::SPDUCertificateChain(sub) => println!("Oh Dear God What Have I done"),
    _ => println!("Nothing happened. Great"),
  }
}
