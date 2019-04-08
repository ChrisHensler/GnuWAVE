pub enum ResultCode {
  Success,
  IncorrectInput,
  NoCertificateProvided,
  NoPublicKeyProvided,
  NotEnoughInfo,
  NoTrustAnchor,
  ChainTooLong,
  NotCryptoValid,
  UnkownCryptoValid,
  InconsistentChainPermissions,
  Revoked,
  Dubious,
  UnsupportedCriticalInfoFields,
  InvalidEncoding,
  CurrTimeBeforeCertValid,
  CurrTimeAfterCertValid,
  ExpireBeforeCertValid,
  ExpireAfterCertValid,
  InvalidGenLocation,
  InconsistentCertPermissions,
  IncorrectReqCertChainLengthForSecProfile,
  IncorrectReqCertChainLengthForImpl
}

enum HashAlgo {
  sha256
}
enum SignerIdType {
  Certificate,
  Digest,
  SelfSigned
}
enum ECPointFormat {
  Compressed,
  Uncompressed
}
enum FastVerificationOptions {
  Compressed,
  Uncompressed,
  No
}

pub struct SignerIdentifier {
  //todo: certificate
  digest[char; 8],
  self_signed=bool,
}

pub struct HeaderInfo {
  psid: u64,
  generation_time: u64,
  expiry_time: u64,
  //generationLocation
}

pub struct HashedData {
  sha256HashedData: [char; 32]
}

pub struct SignedDataPayload {
  data: Ieee1609Dot2DataRaw,  //needed to avoid circular definition
  extDataHash: HashedData
}

pub struct ToBeSignedData {
  payload: SignedDataPayload,
  header_info: HeaderInfo
}

pub struct SignedData  {
  hash_id: HashAlgo,
  tbs_data: ToBeSignedData,
  signer: SignerIdentifier,
  signature: Signature
}

pub struct EncryptedData  {
  //TODO
}

pub struct Ieee1609Dot2Content  {
  unsecured_data: String,
  signed_data: SignedData,
  encrypted_data: EncryptedData,
  signed_cert_data: String
}


pub struct Ieee1609Dot2DataRaw  {
  protocol_version: u8,
  content: String
}
