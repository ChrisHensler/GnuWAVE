use super::access_points::TraitSecureDataService;
use super::super::DataTypes::*;

pub struct SecureDataService {
  s:String,
}
trait PrivateSDS {
  fn get_secret(&self) -> String;
}
impl TraitSecureDataService for SecureDataService {
  fn get_string(&self) -> String {
    String::from("Greetings!")
  }
  fn secret(&self) -> String {
    self.get_secret()
  }
  fn SecSignedDataRaw(&self,
    cryptomaterial_handle: u64,
    data: String,
    ext_data_hash: String,
    ext_data_hash_algo: String,
    psid: u64,
    set_generation_time: bool,
    set_generation_location: bool,
    expiry_time: u64,
    signer_id_type: SignerIdType,
    signer_id_cert_chain_len: u64,
    max_cert_chain_len: u8,
    fast_verification: FastVerificationOptions,
    ec_point_format: ECPointFormat,
    use_p2pcd: bool,
    sdee_id: u64
  ) -> (ResultCode_SecSignedData, Ieee1609Dot2Data)
  {  
    let spdu = Ieee1609Dot2Data {
      protocol_version: 0,
      content: Ieee1609Dot2Content::Unsecured(String::from("Hi"))
    };
    (ResultCode_SecSignedData::Success, spdu)
  }
}

impl PrivateSDS for SecureDataService {
  fn get_secret(&self) -> String {
    String::from("It's a Secret")
  }
}


pub fn new() -> (SecureDataService) {
  SecureDataService {
    s: String::from("Hello there!"),
  }
}
