use std::time::SystemTime;
use super::super::DataTypes;

pub trait TraitSecureDataService {
  fn get_string(&self) -> String;
  fn secret(&self) -> String;

  /*
  Sec-SignedData.request (
    Cryptomaterial Handle,
    Data (optional),
    Data Type (optional),
    External Data Hash (optional),
    External Data Hash Algorithm (optional),
    PSID,
    Set Generation Time,
    Set Generation Location,
    Expiry Time (optional),
    Signer Identifier Type,
    Signer Identifier Certificate Chain Length (optional),
    Maximum Certificate Chain Length (optional),
    Sign With Fast Verification,
    EC Point Format,
    Use Peer-to-Peer Cert Distribution,
    SDEE ID (optional)
  )
  */

  fn SecSignedDataRaw(&self,
    cryptomaterial_handle: u64,
    data: String,
    ext_data_hash: String,
    ext_data_hash_algo: String,
    psid: u64,
    set_generation_time: bool,
    set_generation_location: bool,
    expiry_time: SystemTime,
    signer_id_type: DataTypes::SignerIdType,
    signer_id_cert_chain_len: u64,
    max_cert_chain_len: u8,
    fast_verification: DataTypes::FastVerificationOptions,
    ec_point_format: DataTypes::ECPointFormat,
    use_p2pcd: bool,
    sdee_id: u64
  ) -> (
    ResultCode_SecSignedData, String //todo: ResultCode and IEEEData
  );
}
