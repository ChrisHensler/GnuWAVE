use std::fs;
use super::DataTypes::*;
pub struct DataPlane {
  FilePath: String,
}
impl DataPlane
{
  pub fn GenerateBitStream(&self, data: &Ieee1609Dot2Data) -> String {
    let mut s = (data.protocol_version as char).to_string();
    match &data.content{
      Ieee1609Dot2Content::Unsecured(data_string)=>{
        s.push_str("0");
        s.push_str(&data_string);
      },
      Ieee1609Dot2Content::Signed(SignData)=>{
        s.push_str("1");
        s.push_str("there is no signed data");
      },
      Ieee1609Dot2Content::Encrypted(EncryptData)=>{
        s.push_str("2");
        s.push_str("What even is encryption");
      },
      Ieee1609Dot2Content::SignedCert(cert_string)=>{ 
        s.push_str("3");
        s.push_str("I dont know what a certificate is, please help me");
      },
    }
    s
  }
}
pub fn InitializeDataPlane(s: String) -> DataPlane
{
  DataPlane {
    FilePath: s
  }
}
