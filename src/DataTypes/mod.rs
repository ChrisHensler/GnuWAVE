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
    ret
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
impl Serialization for ToBeSignedData {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    ret.push_str(&self.payload.Serialize());
    ret.push_str(&self.header_info.Serialize());
    ret
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
impl Serialization for HashedData {
  fn Serialize(&self) -> String {
    let mut ret = String::new();
    ret.push_str(&octetslice_to_string(&self.sha256HashedData));
    ret
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
        OptionDataIndicator = OptionDataIndicator|0xBF;
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
