mod Service;
use crate::Service::SDSServices;
//If you try to include the line below, you get a compilation error proving that the trait is private therefore all the methods are private within it asewell.
//use crate::Service::PrivateSDS;
use std::io;
fn main() {
  let test = Service::Initialize();
  println!("Compiled ok {}", test.getString());
  println!("The secret is {}", test.Secret());
}
