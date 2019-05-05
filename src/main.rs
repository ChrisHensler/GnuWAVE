mod security_services;
mod DataTypes;
extern crate rand;
extern crate serde;

use serde::{Serialize, Deserialize};
use crate::DataTypes::*;
use crate::security_services::access_points::TraitSecureDataService;
//If you try to include the line below, you get a compilation error proving that the trait is private therefore all the methods are private within it asewell.
//use crate::Service::PrivateSDS;
use std::io;

fn convert_to_spdu(sds: &security_services::data_service::SecureDataService)  {
  //take param
  println!("enter data");
  let mut input = String::new();
  io::stdin().read_line(&mut input);

  //process
  let result = sds.ConvertToSPDU(input);

  //print result
  //println!("{}",serde_json::to_string(&result).unwrap());
  let mut result_string = "";
  match &result.content {
      Ieee1609Dot2Content::Unsecured(data_string)=>{
        result_string = data_string;
      },
      Ieee1609Dot2Content::Signed(SignData)=>{
        println!("found unexpected signed thing")
      },
      Ieee1609Dot2Content::Encrypted(EncryptData)=>{
        println!("found unexpected encrypted thing")
      },
      Ieee1609Dot2Content::SignedCert(cert_string)=>{
        println!("found unexpected cert signed thing")
      },
    }
  println!("content: {}",result_string);
}

fn main() {
  let mut temp  = DataTypes::generic_ieeedata(DataType::Signed);
  if let Ieee1609Dot2Content::Signed(mut x) = temp.content {
    x.tbs_data.payload.data.content=String::from("no");
    //Must have re-assignment to allow this statement to even exist
    //If you remove temp.content=... then the compiler complains that
    //the value was moved. So I force it to be moved back
    temp.content=Ieee1609Dot2Content::Signed(x);
  }
  println!("{}", temp.Serialize());
  let mut temp2 = DataTypes::generic_ieeedata(DataType::Signed);
  temp2.Deserialize(&temp.Serialize());
  println!("{}", temp2.Serialize());
  println!("{}", temp2.Serialize() == temp.Serialize());
  /*let (sds,ssme) = security_services::initialize();
  println!("Compiled ok {}", sds.get_string());
  let s= ResultCode_SecSignedDataVerification::SPDULocalConsistency(SPDULocalConsistency::PSIDsDontMatch);
  match s {
    ResultCode_SecSignedDataVerification::SPDUParsing(sub) => println!("yay"),  
    ResultCode_SecSignedDataVerification::SPDUCertificateChain(sub) => println!("Oh Dear God What Have I done"),
    _ => println!("Nothing happened. Great"),
  }
  let mut done = false;
  while (!done) {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(n) => {
            println!("{} bytes read", n);
            match input.trim() {
              "convert_to_spdu" => {
                convert_to_spdu(&sds);
              },
              "exit" => {
                done = true;
              },
              _ => {
                println!("unknown command: {}", input)
              }
            }
        }
        Err(error) => println!("error: {}", error),
    }
  }*/
}
