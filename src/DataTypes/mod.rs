//Consider Reading over Annex C. It may have some useful information for us. Its a bit long, but it does... things.
//Consider looking at D.5.1 and beyond for information regarding what they want certificate structure to look like.
//Annex B contains condensed data structure info, including Certificate stuff

//UPDATE: As of 4/23 all Location types should be defined, excluding the bounding ranges on lat,long and elevation. Those should be checked inside struct constrcutor or functional implementation

type TOBEIMPLEMENTED = u8;

//Defining Standards dumb redefines of things
type Psid   = u64;
type Time64 = u64;
type Time32 = u32;
type ThreeDLocation   = [i64;3];
type TwoDLocation     = [i64;2];
type HashedId3        = [char;3];
type HashedId4        = [char;4];
type HashedId8        = [char;8];
type HashedId10       = [char;10];
type HashedId32       = [char;32];
type IValue           = u16;
type Hostname         = String;
type LinkageValue     = [char; 9];
type LinkageSeed      = [char; 16];
type LaId             = [char; 2];
type SubjectAssurance = [char;1];
type CountryOnly      = u16;
type PolygonalRegion  = Vec<TwoDLocation>;
type CrlSeries        = u16;
type CrlPriorityInfo  = u8;
type PermissibleCrls  = SequenceOfCrlSeries;
type PreSharedKeyRecipientInfo = HashedId8;
//##### Sequence Definitions #### /
type SequenceOfPsid   = Vec<Psid>;
type SequenceOfOctect = Vec<Vec<char>>;
type SequenceOfUint16 = Vec<u16>;
type SequenceOfRegionAndSubregions = Vec<RegionAndSubregions>;
type SequenceOfUint8  = Vec<u8>;
type SequenceOfRectangularRegion = Vec<RectangularRegion>;
type SequenceOfIndentifiedRegion = Vec<IdentifiedRegion>;
type SequenceOfPsidGroupPermissions = Vec<PsidGroupPermissions>;
type SequenceOfPsidSspRange         = Vec<PsidSspRange>;
type SequenceOfHashBasedRevocationInfo = Vec<HashBasedRevocationInfo>;
type SequenceOfGroupCrlEntry        = Vec<GroupCrlEntry>;
type SequenceOfIndividualRevocation = Vec<IndividualRevocation>;
type SequenceOfIMaxGroup            = Vec<IMaxGroup>;
type SequenceOfLAGroup              = Vec<LAGroup>;
type SequenceOfJMaxGroup            = Vec<JMaxGroup>;
type SequenceOfCrlSeries            = Vec<CrlSeries>;
type SequenceOfPsidSsp              = Vec<PsidSsp>;
//***********END DUMB REDEFINES*************/

//Read up on the option featuer more. It is actually just a fancy enum with generic types. 
//Essentially like casting to void* but a bit harder to extract the actual info.
//Must use a match statement which handles the "None" (Null) case, and the Some(x) case. In handling the
//Some(x) case x is the value that was put inside the Option (x is just a random variable name. It can be literally anything).
//In order to extract that value, you would need to save it to another temporary storage place. 
//trait Serialization {
//  pub fn Serialize(&self) -> String;
//}
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
pub enum ServiceSpecificPermissions {
  opaque(Vec<char>),
}
pub struct PsidSsp {
  pub psid: Psid,
  pub ssp: Option<ServiceSpecificPermissions>
}
pub enum CracaType {
  IsCraca, IssuerIsCraca,
}
pub struct CrlSsp {
  pub version: u8,
  pub associatedCraca: CracaType,
  pub crls: PermissibleCrls
}
pub struct ToBeSignedLinkageValueCrl {
  pub iRev: IValue,
  pub indexWithinI: u8,
  pub individual: Option<SequenceOfJMaxGroup>,
  pub groups: Option<SequenceOfGroupCrlEntry>
}
pub struct JMaxGroup {
  pub jmax: u8,
  pub contents: SequenceOfLAGroup
}
pub struct LAGroup {
  pub la1Id: LaId,
  pub la2Id: LaId,
  pub contents: SequenceOfIMaxGroup
}
pub struct IMaxGroup {
  pub iMax: u16,
  pub contents: SequenceOfIndividualRevocation
}
pub struct IndividualRevocation {
  pub linkageSeed1: LinkageSeed,
  pub linkageSeed2: LinkageSeed
}
pub struct GroupCrlEntry {
  pub iMax: u16,
  pub la1Id: LaId,
  pub linkageSeed1: LinkageSeed,
  pub la2Id: LaId,
  pub linkageSeed2: LinkageSeed
}
pub enum CrlContentTypes {
  FullHashCrl(ToBeSignedHashIdCrl),
  DeltaHashCrl(ToBeSignedHashIdCrl),
  FullLinkedCrl(ToBeSignedLinkageValueCrl),
  DeltaLinkedCrl(ToBeSignedLinkageValueCrl),
}
pub struct HashBasedRevocationInfo {
  pub id: HashedId10,
  pub expiry: Time32
}
pub struct ToBeSignedHashIdCrl {
  pub crlSeries: u32,
  pub entries: SequenceOfHashBasedRevocationInfo
}
pub struct CrlContents {
  pub version: u8,
  pub crlSeries: CrlSeries,
  pub cracaId: HashedId8,
  pub issueDate: Time32,
  pub nextCrl: Time32,
  pub priorityInfo: Option<CrlPriorityInfo>,
  pub crlType: CrlContentTypes
}
pub enum HashAlgo {
  sha256
}
pub struct RectangularRegion {
  pub northWest: TwoDLocation,
  pub southEast: TwoDLocation
}
pub struct CircularRegion {
  pub center: TwoDLocation,
  pub radius: u16
}
pub enum GeographicRegion {
  CircularRegion(CircularRegion),
  RectangularRegion(SequenceOfRectangularRegion),
  PolygonalRegion(PolygonalRegion),
  IdentifiedRegion(SequenceOfIndentifiedRegion)
}
pub enum IdentifiedRegion {
  CountryOnly(CountryOnly),
  CountryAndRegions(CountryAndRegions),
  CountryAndSubregions(CountryAndSubregions),
}
pub struct CountryAndRegions {
  pub countryOnly: CountryOnly,
  pub regions: SequenceOfUint8
}
pub struct CountryAndSubregions {
  pub country: CountryOnly,
  pub regionAndSubregions: SequenceOfRegionAndSubregions,
}
pub struct RegionAndSubregions {
  pub region: u8,
  pub subregions: SequenceOfUint16
}
pub enum Duration {
  Microseconds(u16),
  Milliseconds(u16),
  Seconds(u16),
  Minutes(u16),
  Hours(u16),
  SixtyHours(u16),
  Years(u16),
}
pub struct ValidityPeriod {
  pub start: Time32,
  pub duration: Duration
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
pub struct PsidSspRange {
  pub psid: Psid,
  pub sspRange: Option<SspRange>
}
pub enum SspRange {
  opaque(SequenceOfOctect),
  all,
}
pub struct IssuerIdentifier {
  pub sha256AndDigest: HashedId8,
  pub hashAlgorithm: HashAlgo
}
pub struct CertificateBase {
  pub version: [u8;3],
  pub certificateType: CertificateType,
  pub issuer: IssuerIdentifier,
  pub toBeSigned: ToBeSignedCertificate,
  pub signature: Option<Signature>
}
pub enum CertificateType {
  Explicit,
  Implicit
}
pub struct ToBeSignedCertificate {
  pub id: CertificateId,
  pub cracaId: HashedId3,
  pub crlSeries: CrlSeries,
  pub validityPeriod: ValidityPeriod,
  pub region: Option<GeographicRegion>,
  pub assuranceLevel: Option<SubjectAssurance>,
  pub appPermissions: Option<SequenceOfPsidSsp>,
  pub certIssuePermissions: Option<SequenceOfPsidGroupPermissions>,
  pub certRequestPermissions: Option<SequenceOfPsidGroupPermissions>,
  pub canRequestRollover: Option<TOBEIMPLEMENTED>,
  pub encryptionKey: Option<TOBEIMPLEMENTED>,
  pub verifyKeyIndicator: Option<TOBEIMPLEMENTED>
}
pub struct GroupLinkageValue {
  pub jValue: [char;4],
  pub value: [char;9]
}
pub enum CertificateId {
  LinkageData(LinkageData),
  Name(String),
  BinaryId([char;64]),
  none
}
pub struct LinkageData {
  pub iCert: IValue,
  pub linkageValue: LinkageValue,
  pub groupLinkageValue: Option<GroupLinkageValue>
}
pub struct PsidGroupPermissions {
  pub appPermisions: SubjectPermissions,
  pub minChainDepth: u64,
  pub chainDepthRange: u64,
  pub eeType: [char;8] //EndEntityType
}
pub enum SubjectPermissions {
  Explicit(SequenceOfPsidSspRange),
  All,
}
pub enum VerificationKeyIndicator {
  VerificationKey(TOBEIMPLEMENTED),
  ReconstructionValue(EccP256CurvePoint),
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
pub enum Algorithm {
  EcdsaBrainPoolP256r1WithSha256,
  EcdsaNistP256WithSha256,
  EciesNistp256,
  EciesBrainpoolP256r1,
  Aes128Ccm,
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
pub struct MissingCrlIdentifier {
  pub cracaId: HashedId3,
  pub crlSeries: CrlSeries
}
pub struct HeaderInfo {
  pub psid: Psid,
  pub generationTime: Option<Time64>,
  pub expiryTime: Option<Time64>,
  pub generationLocation: Option<ThreeDLocation>,
  pub p2pcdLearningRequest: Option<HashedId3>, 
  pub missingCrlIdentifier: Option<MissingCrlIdentifier>,
  pub encryptionKey: Option<TOBEIMPLEMENTED>
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
  pub resultCode: ResultCode_SSMEAddTrustAnchor
}
pub struct SSMEAddCertificateData {
  pub resultCode: ResultCode_SSMECertificateInfo
}
pub struct SSMEVerifyCertificateData {
  pub resultCode: ResultCode_SSMEVerifyCertificate
}
pub struct SSMEDeleteCertificateData {
  pub resultCode: ResultCode_SSMEDeleteCertificate
}
pub struct SSMEAddHashIdBasedRevocationData {
  pub resultCode: ResultCode_SSMEAddHashIdBasedRevocation
}
pub struct SSMEAddIndividualLinkageBasedRevocationData {
  pub resultCode: ResultCode_SSMEAddIndividualLinkageBasedRevocation
}
pub struct SSMEAddGroupLinkageBasedRevocationData {
  pub resultCode: ResultCode_SSMEAddGroupLinkageBasedRevocation
}
pub struct SSMECertificateInfoData {
  pub resultCode: ResultCode_SSMECertificateInfo,
  pub certificateDataVEC: [char;8],
  pub geographicScopeVEC: [char;8],
  pub lastReceiverCRLTime: LastReceivedCRLTime,
  pub nextExpectedCRLTime: NextExpectedCRLTime,
  pub trustAnchor: bool,
  pub verified: bool
}
pub enum SSMERevocationType {
  HashIDBased, LinkageIDBased,
}
pub struct SSMERevocationInformationStatusData {
  pub resultCode: ResultCode_SSMERevocationInformationStatus,
  pub revocationType: SSMERevocationType,
  pub issueDate: i64,
  pub nextCRL: i64
}
pub struct SSMESecIncomingP2pcdInfoData {
  pub RequestActiveForCertificate: bool,
  pub RequestActiveForP2PCDLearningRequest: bool,
  pub ResponseActiveForP2PCDLearningRequest: bool
}
/**********Begin Implementation of Serialization Trait********/
/*impl Serialization for HeaderInfo {
  pub fn Serialize(&self) ->String  {
    String::from("test")
  }
}*/
