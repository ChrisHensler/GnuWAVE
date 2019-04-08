
use super::super::DataTypes::*;
use super::access_points;

pub struct StationSecurityManagementEntity {
  t:String,
}

//Now implement SDServices for SSME
impl access_points::TraitSecureDataService for StationSecurityManagementEntity {
  fn get_string(&self) -> String {
    String::from("Wrong Services package!")
  }
  fn secret(&self) -> String {
    println!("Well shit, you're about to print nothing");
    String::from("nothing")
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
  ) -> (
    ResultCode_SecSignedData, String) {(ResultCode_SecSignedData::Success, String::from("H")) }
}

pub fn new() -> (StationSecurityManagementEntity) {
  StationSecurityManagementEntity {
    t: String::from("Hello there!"),
  }
}
