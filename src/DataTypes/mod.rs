//Consider Reading over Annex C. It may have some useful information for us. Its a bit long, but it does... things.
//Consider looking at D.5.1 and beyond for information regarding what they want certificate structure to look like.
//Annex B contains condensed data structure info, including Certificate stuff

//UPDATE: As of 4/23 all Location types should be defined, excluding the bounding ranges on lat,long and elevation. Those should be checked inside struct constrcutor or functional implementation
extern crate hex;
type TOBEIMPLEMENTED = u8;
type Octet  = u8;
//Defining Standards dumb redefines of things
type Psid   = u64;
type Time64 = u64;
type Time32 = u32;
type ThreeDLocation   = [i64;3];
type TwoDLocation     = [i64;2];
type HashedId3        = [Octet;3];
type HashedId4        = [Octet;4];
type HashedId8        = [Octet;8];
type HashedId10       = [Octet;10];
type HashedId32       = [Octet;32];
type IValue           = u16;
type Hostname         = String;
type LinkageValue     = [Octet; 9];
type LinkageSeed      = [Octet; 16];
type LaId             = [Octet; 2];
type SubjectAssurance = [Octet;1];
type CountryOnly      = u16;
type PolygonalRegion  = Vec<TwoDLocation>;
type CrlSeries        = u16;
type CrlPriorityInfo  = u8;
type PermissibleCrls  = SequenceOfCrlSeries;
type PreSharedKeyRecipientInfo = HashedId8;
//##### Sequence Definitions #### /
type SequenceOfPsid   = Vec<Psid>;
type SequenceOfOctet = Vec<Vec<Octet>>;
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
pub trait Serialization {
  fn Serialize(&self) -> String;
}
pub trait Deserialization {
  fn Deserialize(&mut self, serial: &str);
}
pub enum DataType {
  Unsecured, Signed, Encrypted, SignedCert,
}
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
  opaque(Vec<Octet>),
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
  opaque(SequenceOfOctet),
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
  pub jValue: [Octet;4],
  pub value: [Octet;9]
}
pub enum CertificateId {
  LinkageData(LinkageData),
  Name(String),
  BinaryId([Octet;64]),
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
  pub eeType: [Octet;8] //EndEntityType
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
  xOnly([Octet; 32]),
  fill(),
  compressed_Y_0([Octet; 32]),
  compressed_Y_1([Octet; 32]),
  uncompressed ([Octet; 32],[Octet; 32])
}

pub struct EcdsaP256Signature {
  pub r: EccP256CurvePoint,
  pub s: [Octet; 32]
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
  digest([Octet;8]),
  self_signed(),
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
  pub sha256HashedData: [Octet; 32]
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
  pub certificateDataVEC: [Octet;8],
  pub geographicScopeVEC: [Octet;8],
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
pub enum itype {
  i8(i8),
  i16(i16),
  i32(i32),
  i64(i64),
  i128(i128),
  u8(u8),
  u16(u16),
  u32(u32),
  u64(u64),
  u128(u128),
  f32(f32),
  f64(f64)
}
pub fn remove_spaces(serial: &str) -> String
{
  let mut count =0;
  let mut ret = String::with_capacity(serial.len());
  for i in (0..serial.len())
  {
    if (&serial[i..i+1]!=" ")
    {
      ret.push_str(&serial[i..i+1]);
    }
  }
  ret
}
pub fn u8_vec_to_u16(bytes: &[u8]) -> u16 {
  let mut ret: u16 =0;
  if (bytes.len()<2){
    return ret
  }
  ret = bytes[0] as u16;
  ret = (ret<<8) | bytes[1] as u16;
  ret
}
pub fn u8_vec_to_u64(bytes: &[u8]) -> u64 {
  let mut ret: u64 =0;
  if (bytes.len()<8){
    return ret
  }
  ret = bytes[0] as u64;
  ret = (ret<<8) | bytes[1] as u64;
  ret = (ret<<8) | bytes[2] as u64;
  ret = (ret<<8) | bytes[3] as u64;
  ret = (ret<<8) | bytes[4] as u64;
  ret = (ret<<8) | bytes[5] as u64;
  ret = (ret<<8) | bytes[6] as u64;
  ret = (ret<<8) | bytes[7] as u64;
  ret
}
pub fn u8_vec_to_u32(bytes: &[u8]) -> u32 {
  let mut ret: u32 =0;
  if (bytes.len()<4){
    return ret
  }
  ret = bytes[0] as u32;
  ret = (ret<<8) | bytes[1] as u32;
  ret = (ret<<8) | bytes[2] as u32;
  ret = (ret<<8) | bytes[3] as u32;
  ret
}
pub fn hexstring_to_bytevec(s: &str) -> Vec<u8> {
  let mut ret: Vec<u8> = Vec::new();
  let tp = s.to_lowercase();
  let temp = tp.as_bytes();
  let mut count =0;
  let mut resforpush: u8=0;
  for i in (0..s.len()) {
    let index=i;//s.len()-i-1;
    if (count==0){
      count=1;
      if (temp[index] < 0x3A && temp[index]>=0x30)
      {
        resforpush = (temp[index]&0x0f)<<4;
      }
      else if (temp[index]==0x61) {
        resforpush = 0xa0;
      }
      else if (temp[index]==0x62) {
        resforpush = 0xb0;
        }
      else if (temp[index]==0x63) {
        resforpush = 0xc0;
        }
      else if (temp[index]==0x64) {
        resforpush = 0xd0;
        }
      else if (temp[index]==0x65) {
        resforpush = 0xe0;
        }
      else if (temp[index]==0x66){
        resforpush = 0xf0;
      }
      else {
        count=1;
      }
    }
    else
    {
      count=0;
      if (temp[index] < 0x3A && temp[index]>=0x30)
      {
        resforpush = resforpush|((temp[index]&0x0f));
      }
      else if (temp[index]==0x61){
        resforpush = resforpush |0xa;}
      else if (temp[index]==0x62){
        resforpush = resforpush |0xb;}
      else if (temp[index]==0x63){
        resforpush = resforpush |0xc;}
      else if (temp[index]==0x64){
        resforpush = resforpush |0xd;}
      else if (temp[index]==0x65){
        resforpush = resforpush |0xe;}
      else if (temp[index]==0x66){
        resforpush = resforpush |0xf;}
      else {
        count=1;
      }
      if (count==0) {
        ret.push(resforpush);
      }
    }
  }
  ret
}

fn convert_to_u8vec(variable: itype) -> Vec<u8>
{
  let mut ret: Vec<u8> = Vec::new();
  match variable {
    itype::i8(x) => {
      ret.push(x as u8);
    },
    itype::i16(x) => {
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::i32(x) => {
      ret.push(((x>>24)&0xff)as u8);
      ret.push(((x>>16)&0xff)as u8);
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::i64(x) => {
      ret.push(((x>>56)&0xff)as u8);
      ret.push(((x>>48)&0xff)as u8);
      ret.push(((x>>40)&0xff)as u8);
      ret.push(((x>>32)&0xff)as u8);
      ret.push(((x>>24)&0xff)as u8);
      ret.push(((x>>16)&0xff)as u8);
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::i128(x) => {
      ret.push(((x>>120)&0xff)as u8);
      ret.push(((x>>112)&0xff)as u8);
      ret.push(((x>>104)&0xff)as u8);
      ret.push(((x>>96)&0xff)as u8);
      ret.push(((x>>88)&0xff)as u8);
      ret.push(((x>>80)&0xff)as u8);
      ret.push(((x>>72)&0xff)as u8);
      ret.push(((x>>64)&0xff)as u8);
      ret.push(((x>>56)&0xff)as u8);
      ret.push(((x>>48)&0xff)as u8);
      ret.push(((x>>40)&0xff)as u8);
      ret.push(((x>>32)&0xff)as u8);
      ret.push(((x>>24)&0xff)as u8);
      ret.push(((x>>16)&0xff)as u8);
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::u8(x) => {
      ret.push(x as u8);
    },
    itype::u16(x) => {
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::u32(x) => {
      ret.push(((x>>24)&0xff)as u8);
      ret.push(((x>>16)&0xff)as u8);
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::u64(x) => {
      ret.push(((x>>56)&0xff)as u8);
      ret.push(((x>>48)&0xff)as u8);
      ret.push(((x>>40)&0xff)as u8);
      ret.push(((x>>32)&0xff)as u8);
      ret.push(((x>>24)&0xff)as u8);
      ret.push(((x>>16)&0xff)as u8);
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    itype::u128(x) => {
      ret.push(((x>>120)&0xff)as u8);
      ret.push(((x>>112)&0xff)as u8);
      ret.push(((x>>104)&0xff)as u8);
      ret.push(((x>>96)&0xff)as u8);
      ret.push(((x>>88)&0xff)as u8);
      ret.push(((x>>80)&0xff)as u8);
      ret.push(((x>>72)&0xff)as u8);
      ret.push(((x>>64)&0xff)as u8);
      ret.push(((x>>56)&0xff)as u8);
      ret.push(((x>>48)&0xff)as u8);
      ret.push(((x>>40)&0xff)as u8);
      ret.push(((x>>32)&0xff)as u8);
      ret.push(((x>>24)&0xff)as u8);
      ret.push(((x>>16)&0xff)as u8);
      ret.push(((x>>8)&0xff)as u8);
      ret.push((x&0xff)as u8);
    },
    _ => ret.push(0),
  }
  ret
}
fn octetslice_to_string(s: &[Octet]) -> String {
  let mut ret = String::new();
  let mut vt: Vec<u8> = Vec::new();
  for i in (0..s.len())
  {
    vt.append(&mut convert_to_u8vec(itype::u8(s[i] as u8)));
  }
  ret.push_str(&hex::encode(vt));
  ret
}
impl Serialization for Ieee1609Dot2Data {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    ret.push_str(&hex::encode(convert_to_u8vec(itype::u8(self.protocol_version))));
    match &self.content {
      Ieee1609Dot2Content::Unsecured(x) => {
        ret.push_str("00");
        //ret.push_str(&hex::encode(convert_to_u8vec(itype::u16(x.len() as u16))));
        ret.push_str(&hex::encode(&x));
      },
      Ieee1609Dot2Content::Signed(x) => {
        ret.push_str("01");
        ret.push_str(&x.Serialize());
      },
      Ieee1609Dot2Content::Encrypted(x) => {
        ret.push_str("02");
      },
      Ieee1609Dot2Content::SignedCert(x) => {
        ret.push_str("03");
        //ret.push_str(&hex::encode(convert_to_u8vec(itype::u16(x.len() as u16))));
        ret.push_str(&hex::encode(&x));
      },
    }
    ret
  }
}
impl Deserialization for Ieee1609Dot2Data {
  fn Deserialize(&mut self, serial: &str)
  {
    let mut data = hexstring_to_bytevec(&serial);
    let mut bytecount =0;
    self.protocol_version = data[0];
    bytecount=bytecount+1;
    data = data[1..].to_vec();
    bytecount=bytecount+1;
    if (data[0]==0) {
      let mut temp = String::with_capacity(data.len());
      for i in (0..data.len()-1)
      {
        temp.insert(i, data[i+1] as char);
      }
      self.content = Ieee1609Dot2Content::Unsecured(temp);
    }
    else if (data[0] ==1) {
      let mut temp= SignedData  {
      hash_id: HashAlgo::sha256,
      tbs_data:
        ToBeSignedData {
          payload: 
            SignedDataPayload  {
              data: 
                Ieee1609Dot2DataRaw  {
                  protocol_version: 0,
                  content: String::new(),
                },
              extDataHash: HashedData {
                sha256HashedData: [0; 32]
              }
            },
          header_info:
            HeaderInfo {
              psid: 0,
              generationTime: None,
              expiryTime: None,
              generationLocation: None,
              p2pcdLearningRequest: None,
              missingCrlIdentifier: None,
              encryptionKey: None
            },
          },
      signer: SignerIdentifier::self_signed(),
      signature: Signature::ecdsaNistP256Signature(EcdsaP256Signature {
          r: EccP256CurvePoint::fill(),
          s: [0; 32],
        })
      };
      temp.Deserialize(&serial[bytecount*2..]);
      self.content = Ieee1609Dot2Content::Signed(temp);
    }
    else if (data[0] ==2) {
      //TO BE IMPLEMENTED;
    }
    else if (data[0] ==3) {
      let mut temp = String::with_capacity(data.len());
      for i in (0..data.len()-1)
      {
        temp.insert(i, data[i+1] as char);
      }
      self.content = Ieee1609Dot2Content::SignedCert(temp);
    }
  }
}
impl Serialization for SignedData {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    //Hash Algo
    ret.push_str("01");
    //tbs data
    let temp = self.tbs_data.Serialize();
    //len/2 since the number of bytes is half the number of chars
    ret.push_str(&hex::encode(&convert_to_u8vec(itype::u16((temp.len()/2) as u16))));
    ret.push_str(&temp);
    match &self.signer {
      SignerIdentifier::Certificate(x) => {
        ret.push_str("00");
        ret.push_str(&hex::encode(&convert_to_u8vec(itype::u16((x.len()/2) as u16))));
        ret.push_str(&x);
      },
      SignerIdentifier::digest(x) => {        
        ret.push_str("01");
        ret.push_str(&octetslice_to_string(x));
      },
      SignerIdentifier::self_signed() => {
        ret.push_str("02");
      },
    }
    match &self.signature {
      Signature::ecdsaNistP256Signature(x) => {
        ret.push_str("00");
        ret.push_str(&x.Serialize());
      },
      Signature::ecdsaBrainpoolP256r1Signature(x) => {
        ret.push_str("01");
        ret.push_str(&x.Serialize());
      },
    }
    ret
  }
}
impl Deserialization for SignedData {
  fn Deserialize(&mut self, serial: &str)
  {
    //println!("SignedData\n{}", serial);
    //println!("{}", serial.len());
    let mut data=hexstring_to_bytevec(&serial);
    let mut bytecount=0;
    if (data[0] == 1)
    {
      self.hash_id=HashAlgo::sha256;
      bytecount=1;
    }
    let tbs_size = u8_vec_to_u16(&data[bytecount..bytecount+2]) as usize;
    bytecount= bytecount+2;
    //println!("{} {} {}", tbs_size, bytecount, (bytecount+tbs_size)*2);
    self.tbs_data.Deserialize(&serial[bytecount*2..(bytecount+tbs_size)*2]);
    bytecount= bytecount+tbs_size;
    data=hexstring_to_bytevec(&serial[bytecount*2..]);
    let signid= data[0];
    bytecount = bytecount+1;
    if (signid==0) {
      let certsize= u8_vec_to_u16(&data[1..3]) as usize;
      bytecount=bytecount+2;
      data=data[3..].to_vec();
      let mut temp = String::with_capacity(certsize);
      for i in (0..certsize)
      {
        temp.insert(i, data[i] as char);
      }
      self.signer = SignerIdentifier::Certificate(temp);
      bytecount = bytecount+certsize;
      data=data[certsize..].to_vec();
    }
    else if (signid ==1)
    {
      let mut dig: [Octet;8] = [0 as Octet;8];
      for i in (0..8)
      {
        dig[i] = data[i+1];
      }
      bytecount=bytecount+8;
      self.signer = SignerIdentifier::digest(dig);
      data=data[9..].to_vec();
    }
    else if (signid==3)
    {
      self.signer=SignerIdentifier::self_signed();
      data=data[1..].to_vec();
    }
    let sigtype = data[0];
    bytecount=bytecount+1;
    let mut temp = EcdsaP256Signature{
      r: EccP256CurvePoint::fill(),
      s: [0 as Octet;32],
    };
    temp.Deserialize(&serial[bytecount*2..]);
    if (sigtype == 0)
    {
      self.signature=Signature::ecdsaNistP256Signature(temp);
    }
    else if (sigtype ==1)
    {
      self.signature=Signature::ecdsaBrainpoolP256r1Signature(temp);
    }
  }
}
impl Serialization for EcdsaP256Signature {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    match self.r {
      EccP256CurvePoint::xOnly(x) => {
        ret.push_str("00");  
        ret.push_str(&octetslice_to_string(&x));
      },
      EccP256CurvePoint::fill() => {
        ret.push_str("01");  
      },
      EccP256CurvePoint::compressed_Y_0(x) => {
        ret.push_str("02");
        ret.push_str(&octetslice_to_string(&x));
      },
      EccP256CurvePoint::compressed_Y_1(x) => {
        ret.push_str("03");  
        ret.push_str(&octetslice_to_string(&x));
      },
      EccP256CurvePoint::uncompressed(x,y) => {
        ret.push_str("04");
        ret.push_str(&octetslice_to_string(&x));
        ret.push_str(&octetslice_to_string(&y));
      },
    }
    ret.push_str(&octetslice_to_string(&self.s));
    ret
  }
}
impl Deserialization for EcdsaP256Signature {
  fn Deserialize(&mut self, serial: &str)
  {
    let mut data = hexstring_to_bytevec(&serial);
    let option = data[0];
    if (option==0) {
      let mut temp: [Octet;32]=[0 as Octet;32];
      for i in (0..32) {
        temp[i]=data[i+1];
      }
      self.r=EccP256CurvePoint::xOnly(temp);
      data=data[33..].to_vec();
    }
    else if (option == 1) {
      self.r=EccP256CurvePoint::fill();
    }
    else if (option == 2) {
      let mut temp: [Octet;32]=[0 as Octet;32];
      for i in (0..32) {
        temp[i]=data[i+1];
      }
      self.r=EccP256CurvePoint::compressed_Y_0(temp);
      data=data[33..].to_vec();

    }
    else if (option == 3) {
      let mut temp: [Octet;32]=[0 as Octet;32];
      for i in (0..32) {
        temp[i]=data[i+1];
      }
      self.r=EccP256CurvePoint::compressed_Y_1(temp);
      data=data[33..].to_vec();

    }
    else if (option == 4) {
      let mut temp: [Octet;32]=[0 as Octet;32];
      let mut temp2: [Octet;32]=[0 as Octet;32];
      for i in (0..32) {
        temp[i]=data[i+1];
      }
      data=data[33..].to_vec();
      for i in (0..32) {
        temp2[i]=data[i];
      }
      self.r=EccP256CurvePoint::uncompressed(temp,temp2);
      data=data[32..].to_vec();
    }
    else
    {
      data=data[1..].to_vec();
    }
    let mut temp: [Octet;32] = [0 as Octet;32];
    for i in (0..32)
    {
      temp[i]=data[i];
    }
    self.s = temp;
  }
}
impl Serialization for MissingCrlIdentifier {
  fn Serialize(&self) -> String  {
    let mut ret=String::new();
    let mut s = vec![];
    s.extend_from_slice(&self.cracaId);
    ret.push_str(&hex::encode(s));
    ret.push_str(&hex::encode(convert_to_u8vec(itype::u16(self.crlSeries))));
    ret
  }
}
impl Deserialization for MissingCrlIdentifier {
  fn Deserialize(&mut self, serial: &str) {
    let s = hexstring_to_bytevec(&serial);
    self.cracaId[0]=s[0];
    self.cracaId[1]=s[1];
    self.cracaId[2]=s[2];
    self.crlSeries=u8_vec_to_u16(&s[3..5]);
  }
}
//MAY NEED TO INCLUDE SIZE OF PAYLOAD IN DATA STRUCT
impl Serialization for ToBeSignedData {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    let temp = self.payload.Serialize();
    let size: u16 = (temp.len()/2) as u16;
    ret.push_str(&hex::encode(&convert_to_u8vec(itype::u16(size))));
    ret.push_str(&self.payload.Serialize());
    ret.push_str(&self.header_info.Serialize());
    ret
  }
}
impl Deserialization for ToBeSignedData {
  fn Deserialize(&mut self, serial: &str)
  {
    //println!("ToBeSigned\n{}", serial);
    //println!("{}", serial.len());
    let mut bytecount = 0;
    let data = hexstring_to_bytevec(&serial[0..4]);
    let payload_size= u8_vec_to_u16(&data[0..2]) as usize;
    bytecount=bytecount+2;
    //println!("{}", payload_size);
    self.payload.Deserialize(&serial[bytecount*2..((payload_size+bytecount)*2)]);
    bytecount=bytecount+payload_size;
    self.header_info.Deserialize(&serial[(bytecount*2)..]);
  }
}
impl Serialization for SignedDataPayload {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    ret.push_str(&self.data.Serialize());
    ret.push_str(&self.extDataHash.Serialize());
    ret
  }
}
impl Deserialization for SignedDataPayload {
  fn Deserialize(&mut self, serial: &str) {
    //println!("SignedDataPayload\n{}", serial);
    //println!("{} {}", serial.len(), serial.len()-64);
    self.data.Deserialize(&serial[0..serial.len()-64]);
    self.extDataHash.Deserialize(&serial[serial.len()-64..]);
  }
}
impl Serialization for HashedData {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    ret.push_str(&octetslice_to_string(&self.sha256HashedData));
    ret
  }
}
impl Deserialization for HashedData {
  fn Deserialize(&mut self, serial: &str) {
    let s = hexstring_to_bytevec(&serial);
    for i in (0..s.len())
    {
      self.sha256HashedData[i]=s[i];
    }
  }
}
impl Serialization for Ieee1609Dot2DataRaw {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    ret.push_str(&hex::encode(convert_to_u8vec(itype::u8(self.protocol_version))));
    ret.push_str(&hex::encode(&self.content));
    ret
  }
}
impl Deserialization for Ieee1609Dot2DataRaw {
  fn Deserialize(&mut self, serial: &str) {
    let s = hexstring_to_bytevec(&serial);
    //println!("Ieee1609Dot2DataRaw\n{}\n {} {}", serial, serial.len(), s.len());
    self.protocol_version=s[0];
    let mut string = String::with_capacity(serial.len());
    for i in (0..s.len()-1) {
      string.insert(i, s[i+1] as char);
    }
    //println!("Raw_string:{}", string);
    self.content = string;
  }
}
impl Serialization for HeaderInfo {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    let String_Psid    = convert_to_u8vec(itype::u64(self.psid));
    let mut String_Options = String::new(); 
    let mut OptionDataIndicator: u8 =0;
    
    match self.generationTime {
      Some(x) => {
        OptionDataIndicator= OptionDataIndicator|0x01;
        String_Options.push_str(&hex::encode(convert_to_u8vec(itype::u64(x))));
      },
      None => {
        OptionDataIndicator = OptionDataIndicator&0xFE;
      },
    }

    match self.expiryTime {
      Some(x) => {
        OptionDataIndicator= OptionDataIndicator|0x02;
        String_Options.push_str(&hex::encode(convert_to_u8vec(itype::u64(x))));
      },
      None => {
        OptionDataIndicator = OptionDataIndicator&0xFD;
      },
    }

    match self.generationLocation {
      Some(x) => {
        OptionDataIndicator = OptionDataIndicator|0x04;
        String_Options.push_str(&hex::encode(convert_to_u8vec(itype::i64(x[0]))));
        String_Options.push_str(&hex::encode(convert_to_u8vec(itype::i64(x[1]))));
        String_Options.push_str(&hex::encode(convert_to_u8vec(itype::i64(x[2]))));
      },
      None => {
        OptionDataIndicator = OptionDataIndicator&0xFB;
      },
    }
    match self.p2pcdLearningRequest {
      Some(x) => {
        OptionDataIndicator = OptionDataIndicator|0x08;
        String_Options.push_str(&octetslice_to_string(&x));
      },
      None => {
        OptionDataIndicator = OptionDataIndicator&0xF7;
      },
    }
    match &self.missingCrlIdentifier {
      Some(x) => {
        OptionDataIndicator = OptionDataIndicator|0x10;
        String_Options.push_str(&(x.Serialize()));
      },
      None => {
        OptionDataIndicator = OptionDataIndicator&0xEF;
      },
    }
    match self.encryptionKey{
      Some(x) => {
        OptionDataIndicator = OptionDataIndicator|0x20;
        String_Options.push_str(&hex::encode(convert_to_u8vec(itype::u8(x))));
      },
      None => {
        OptionDataIndicator = OptionDataIndicator&0xDF;
      },
    }
    ret.push_str(&hex::encode(String_Psid));
    ret.push_str(&hex::encode(convert_to_u8vec(itype::u8(OptionDataIndicator))));
    ret.push_str(&String_Options);
    ret
  }
}
impl Deserialization for HeaderInfo {
  fn Deserialize(&mut self, serial: &str)
  {
    //Written under the assumption that all whitespaces have been removed from the hexstring
    let temp = hexstring_to_bytevec(&serial);
    self.psid = u8_vec_to_u64(&temp);
    let options = temp[8];
    let mut data=temp[9..].to_vec();
    let mut bytecount=9;
    if (options & 0x01 == 0x01)
    {
      if (data.len()>=8)
      {
        self.generationTime = Some(u8_vec_to_u64(&data[0..8]));
        bytecount= bytecount+8;
      }
      if (data.len()>8) {
        data=data[8..].to_vec();
      }
    }
    else {
      self.generationTime=None;
    }

    if (options & 0x02 == 0x02)
    {
      if (data.len()>=8) {
        self.expiryTime = Some(u8_vec_to_u64(&data[0..8]));
        bytecount=bytecount+8;
      }
      if (data.len()>8) {
        data=data[8..].to_vec();
      }
    }
    else {
      self.expiryTime=None;
    }

    if (options & 0x04 == 0x04) 
    {
      let mut s: [i64;3]=[0,0,0];
      if (data.len()>=24) {
      s[0]=u8_vec_to_u64(&data[0..8]) as i64;
      s[1]=u8_vec_to_u64(&data[8..16]) as i64;
      s[2]=u8_vec_to_u64(&data[16..24]) as i64;
      bytecount= bytecount+24;
      }
      self.generationLocation = Some(s);
      if (data.len()>24) {
        data=data[24..].to_vec();
      }
    }

    else {
      self.generationLocation=None;
    }
    if (options &0x08 == 0x08)
    {
      let mut s:HashedId3 = [0,0,0];
      if (data.len()>=3) {
        s[0]=data[0] as Octet;
        s[1]=data[1] as Octet;
        s[2]=data[2] as Octet;
        self.p2pcdLearningRequest=Some(s);
      }
      if (data.len()>3)
      {
        data=data[3..].to_vec();
      }
    }
    else {
      self.p2pcdLearningRequest=None;
    }

    if (options & 0x10 == 0x10) 
    {
      if (data.len()>=5)
      {
        let mut s = MissingCrlIdentifier {cracaId:[0,0,0],crlSeries:0,};
        s.Deserialize(&serial[bytecount*2..(bytecount+5)*2]);
        self.missingCrlIdentifier=Some(s);
        bytecount=bytecount+5;
      }
      if (data.len()>5)
      {
        data=data[5..].to_vec();
      }
    }
    else {
      self.missingCrlIdentifier=None;
    }

    if (options & 0x20 == 0x20)
    {
      if (data.len()>=1)
      {
        self.encryptionKey=Some(data[0]);
        bytecount= bytecount+1;
      }
    }
    else {
      self.encryptionKey=None;
    }
  }
}
pub fn generic_ieeedata(dtype:DataType ) -> Ieee1609Dot2Data{
  match dtype {
    DataType::Signed => {
      let to_be_signed = ToBeSignedData {
        payload: SignedDataPayload  {
          data: Ieee1609Dot2DataRaw  {
            protocol_version: 0,
            content: String::from("yas"),
          },
          extDataHash: HashedData {
            sha256HashedData: [0; 32]
          }
        },
        header_info: HeaderInfo {
          psid: 0,
          generationTime: None,
          expiryTime: None,
          generationLocation: None,
          p2pcdLearningRequest: None,
          missingCrlIdentifier: None,
          encryptionKey: None
        },
      };

      let content = Ieee1609Dot2Content::Signed(SignedData  {
        hash_id: HashAlgo::sha256,
        tbs_data: to_be_signed,
        signer: SignerIdentifier::self_signed(),
        signature: Signature::ecdsaNistP256Signature(EcdsaP256Signature {
            r: EccP256CurvePoint::fill(),
            s: [0; 32],
          })
      });

      let spdu = Ieee1609Dot2Data {
        protocol_version: 0,
        content: content
      };
      spdu
      },
    DataType::Unsecured => {
      let content = Ieee1609Dot2Content::Unsecured(String::from("WHAT"));
      let spdu = Ieee1609Dot2Data {
        protocol_version: 0,
        content: content
      };
      spdu
    },
    _ => {
      let content = Ieee1609Dot2Content::Unsecured(String::from(""));
      let spdu = Ieee1609Dot2Data {
        protocol_version: 0,
        content: content
      };
      spdu
    },

  }
}
