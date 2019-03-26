pub trait TraitSecureDataService {
  fn get_string(&self) -> String;
  fn secret(&self) -> String;
}