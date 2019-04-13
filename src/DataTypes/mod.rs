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
  pub r: EccP256CurvePoint,
  pub s: [char; 32]
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
  pub psid: u64,
  pub generation_time: u64,
  pub expiry_time: u64,
}

pub struct HashedData {
  pub sha256HashedData: [char; 32]
}

pub struct SignedDataPayload {
  pub data: Ieee1609Dot2DataRaw,  //needed to avoid circular definition
  pub extDataHash: HashedData
}

pub struct ToBeSignedData {
  pub payload: SignedDataPayload,
  pub header_info: HeaderInfo
}

pub struct SignedData  {
  pub hash_id: HashAlgo,
  pub tbs_data: ToBeSignedData,
  pub signer: SignerIdentifier,
  pub signature: Signature
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
  pub protocol_version: u8,
  pub content: Ieee1609Dot2Content
}

pub struct Ieee1609Dot2DataRaw  {
  pub  protocol_version: u8,
  pub content: String
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
pub enum ResultCode_SSMECertificateInfo {
  CertificateNotFound, MultipleCertificatesIdentified, NotYetVerified, VerifiedAndTrusted, NoTrustAnchor, ChainTooLongForImplementation, NotCryptographicallyValid, InconsistentPermissionsInChain, Revoked, Dubious, UnsupportedCriticalInformationFields, InvalidEncoding,
}
pub enum ResultCode_SSMEAddTrustAnchor {
  Success, InvalidInput, CertificateRevoked, CertificateDidNotVerify,
}
pub enum ResultCode_SSMEAddCertificate {
  Success, InvalidInput,
}
pub enum ResultCode_SSMEVerifyCertificate {
  Verified, NoTrustAnchor, ChainTooLongForImplementation, NotCryptographicallyValid, InconsistentPermissionsInChain, Revoked, Dubious, UnsupportedCriticalInformationFields, InvalidEncoding,
}
pub enum ResultCode_SSMEDeleteCertificate {
  Success, InvalidInput,
}
pub enum ResultCode_SSMEAddHashIdBasedRevocation {
  Success, InvalidInput,
}
pub enum ResultCode_SSMEAddIndividualLinkageBasedRevocation {
  Success,InvalidInput,
}
pub enum ResultCode_SSMEAddGroupLinkageBasedRevocation {
  Success,InvalidInput,
}
pub enum ResultCode_SSMERevocationInformationStatus {
  Success, UnrecognizedIdentifier, Expired, NotIssuedYet, Missing,
}
pub enum ResultCode_SSMEP2pcdConfiguration {
  Success,Failure,
}
pub enum ResultCode_SSMESecReplayDetection {
  Replay,NotReplay,
}
pub enum LastReceivedCRLTime {
  Date(i64),
  NONE,
}
pub enum NextExpectedCRLTime {
  Date(i64),
  Unknown,
}
pub enum IdentifierType_SSMECertificateInfo {
  Certificate, HashedId8, HashedId10,
}
//Anyhting that contians VEC may be replaced a vector of octects so that they can have a variable number contained
pub struct SSMEAddTrustAnchorData {
  pub ResultCode: ResultCode_SSMEAddTrustAnchor
}
pub struct SSMEAddCertificateData {
  pub ResultCode: ResultCode_SSMECertificateInfo
}
pub struct SSMEVerifyCertificateData {
  pub ResultCode: ResultCode_SSMEVerifyCertificate
}
pub struct SSMEDeleteCertificateData {
  pub ResultCode: ResultCode_SSMEDeleteCertificate
}
pub struct SSMEAddHashIdBasedRevocationData {
  pub ResultCode: ResultCode_SSMEAddHashIdBasedRevocation
}
pub struct SSMEAddIndividualLinkageBasedRevocationData {
  pub ResultCode: ResultCode_SSMEAddIndividualLinkageBasedRevocation
}
pub struct SSMEAddGroupLinkageBasedRevocationData {
  pub ResultCode: ResultCode_SSMEAddGroupLinkageBasedRevocation
}
pub struct SSMECertificateInfoData {
  pub ResultCode: ResultCode_SSMECertificateInfo,
  pub CertificateDataVEC: [char;8],
  pub GeographicScopeVEC: [char;8],
  pub LastReceiverCRLTime: LastReceivedCRLTime,
  pub NextExpectedCRLTime: NextExpectedCRLTime,
  pub TrustAnchor: bool,
  pub Verified: bool
}
pub enum SSMERevocationType {
  HashIDBased, LinkageIDBased,
}
pub struct SSMERevocationInformationStatusData {
  pub ResultCode: ResultCode_SSMERevocationInformationStatus,
  pub RevocationType: SSMERevocationType,
  pub IssueDate: i64,
  pub NextCRL: i64
}
pub struct SSMESecIncomingP2pcdInfoData {
  pub RequestActiveForCertificate: bool,
  pub RequestActiveForP2PCDLearningRequest: bool,
  pub ResponseActiveForP2PCDLearningRequest: bool
}

