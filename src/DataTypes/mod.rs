pub enum ResultCode_SecSignedData {
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
  IncorrectReqCertChainLengthForImpl,
}

pub enum HashAlgo {
  sha256
}
pub enum SignerIdType {
  Certificate,
  Digest,
  SelfSigned
}
pub enum ECPointFormat {
  Compressed,
  Uncompressed
}
pub enum FastVerificationOptions {
  Compressed,
  Uncompressed,
  No
}

pub enum EccP256CurvePoint {
  xOnly([char; 32]),
  fill(),
  compressed_Y_0([char; 32]),
  compressed_Y_1([char; 32]),
  uncompressed ([char; 32],[char; 32])
}

pub struct EcdsaP256Signature {
  r: EccP256CurvePoint,
  s: [char; 32]
}

pub enum Signature {
  ecdsaNistP256Signature(EcdsaP256Signature),
  ecdsaBrainpoolP256r1Signature(EcdsaP256Signature),
} 

pub enum SignerIdentifier {
  Certificate(String),
  digest([char;8]),
  self_signed(bool),
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

enum Ieee1609Dot2ContentType {
  Unsecured,
  Signed,
  Encrypted,
  SignedCert,
}

pub enum Ieee1609Dot2Content  {
  Unsecured(String),
  Signed(SignedData),
  Encrypted(EncryptedData),
  SignedCert(String)
}

pub struct Ieee1609Dot2Data  {
  protocol_version: u8,
  content: Ieee1609Dot2Content
}

pub struct Ieee1609Dot2DataRaw  {
  protocol_version: u8,
  content: String
}
pub enum ResultCode_SecEncryptedData {
  Success, IncorrectInputs, FailOnSomeCertificates, FailOnAllCertificates,
}
pub enum ResultCode_SecSecureDataPreProcess {
  Success, InvalidInput, UnknownCertificate, InconsistentPSID,
}
pub enum SPDUParsing {
  InvalidInput, UnsupportedCriticalInfoField, CertificateNotFound, GenerationTimeNotAvailable, GenerationLocationNotAvailable,
}
pub enum SPDUCertificateChain {
  NotEnoughInfoToConstructChain,ChainEndedAtUntrustedRoot, ChainWasTooLongForImplementation, CertificateRevoked, OverdueCRL, InconsistentExpiryTimes,InconsistentStartTimes,InconsistentChainPermissions,
}
pub enum SPDUConsistency {
  FutureCertificateAtGenerationTime, ExpiredCertificateAtGenerationTime, ExpiryDateTooEarly,ExpiryDateTooLate, GenerationLocationOutsideValidityRegion, NoGenerationLocation, UnauthorizedPSID,
}
pub enum SPDUCrypto {
  VerificationFailure,
}
pub enum SPDUInternalConsistency {
  ExpiryTimeBeforeGenerationTime, ExtDataHashDoesntMatch, NoExtDataHashProvided, NoExtDataHashPresent,
}
pub enum SPDULocalConsistency {
  PSIDsDontMatch, ChainWasTooLongForSDEE,
}
pub enum SPDURelevance {
  GenerationTimeTooFarInPast, GenerationTimeTooFarInFuture, ExpiryTimeInPast, GenerationLocationTooDistant, ReplayedSPDU, CertificateExpired,
}
pub enum ResultCode_SecSignedDataVerification {
  SPDUParsing(SPDUParsing),
  SPDUCertificateChain(SPDUCertificateChain),
  SPDUConsistency(SPDUConsistency),
  SPDUCrypto(SPDUCrypto),
  SPDUInternalConsistency(SPDUInternalConsistency),
  SPDULocalConsistency(SPDULocalConsistency),
  SPDURelevance(SPDURelevance),
}
pub enum ResultCode_SecEncryptedDataDecryption {
  Success,NoDecryptionKeyAvailable,UnsupportedCriticalInformationField,CouldntDecryptKey,CouldntDecryptData,InvalidFormForPlainText,
}

