pub struct SDS{
  s:String,
}

pub trait TraitSecureDataService {
  fn getString(&self) -> String;
  fn Secret(&self) -> String;
}


trait PrivateSDS {
  fn getSecret(&self) -> String;
}

impl TraitSecureDataService for SDS {
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


pub fn Initialize() -> (SDS) {
  let  r=SDS {
    s: String::from("Hello there!"),
    };
  r
}