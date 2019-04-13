use super::DataTypes::*;
pub trait Tester{
  fn getme(&self) -> String;
}
pub trait SSMETraits {
  fn CertificateInfo(&self,IdentifierType: IdentifierType_SSMECertificateInfo, Identifier: [char;8]) -> SSMECertificateInfoData;
  fn AddTrustAnchor(&self) -> SSMEAddTrustAnchorData;
  fn AddCertificate(&self) -> SSMEAddCertificateData;
  fn VerifyCertificate(&self) -> SSMEVerifyCertificateData;
  fn DeleteCertificate(&self) -> SSMEDeleteCertificateData;
  fn AddHashIdBasedRevocation(&self) -> SSMEAddHashIdBasedRevocationData;
  fn AddIndividualLinkageBasedRevocation(&self) -> SSMEAddIndividualLinkageBasedRevocationData;
  fn AddGroupLinkageBasedRevocation(&self) -> SSMEAddGroupLinkageBasedRevocationData;
  fn AddRevocationInfo(&self) -> SSMEAddRevocationInfoData;
  fn RevocationInformationStatus(&self) -> SSMERevocationInformationStatusData;
  fn P2pcdResponseGenerationService(&self) -> SSMEP2pcdResponseGenerationServiceData;
  fn P2pcdConfiguration(&self) -> SSMEP2pcdConfigurationData;
}
