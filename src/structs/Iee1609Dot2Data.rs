
// 6.3.4 SignedData
// SignedData ::= SEQUENCE {
// hashId HashAlgorithm,
// tbsData ToBeSignedData,
// signer SignerIdentifier,
// signature Signature
// }
// In this structure:
//  hashId indicates the hash algorithm to be used to generate the hash of the message for signing
// and verification.
//  tbsData contains the data that is hashed as input to the signature.
//  signer determines the keying material and hash algorithm used to sign the data.
//  signature contains the digital signature itself, calculated as specified in 5.3.1, with:
//  Data input equal to the COER encoding of the tbsData field canonicalized according to
// the encoding considerations given in 6.3.6.
//  Verification type equal to certificate.
//  Signer identifier input equal to the COER-encoding of the Certificate that is to be used
// to verify the SPDU, canonicalized according to the encoding considerations given in 6.4.3.

struct SignedData {
    hashId: HashAlgorithm,
    tbsData: ToBeSignedData,
    signer: SignerIdentifier,
    signature: Signature,
}



// Subclause 6.3 specifies the secured protocol data unit (SPDU) structures created and consumed by the SDS.
// A SPDU is an Ieee1609Dot2Data as defined in 6.3.
// The order in which the structures are defined below is hierarchical based on the first use in a prior structure.
//
// For example, in 6.2.2 Ieee1609Dot2Data is defined using several structures, of which the first three are
// Opaque (a synonym for OCTET STRING, see 6.2), SignedData, and EncryptedData. Subsequently,
// SignedData is defined in 6.3.4, and EncryptedData is defined in 6.3.30. The subclauses between 6.3.4 and
// 6.3.30 are used to define structures used within SignedData, and so on. (Exceptions are the fields associated
// with MissingCrlIdentifier, which are defined in 7.3 in order to keep all CRL-related fields in one place).
// Additionally, in the electronic version of the standard, all uses of a structure name are hyperlinked to the
// title of the subclause that defines the structure.

struct Iee1609Dot2Content {
    unsecuredData: String,
    signedData: SignedData,
    encryptedData: EncryptedData,
    signedCertificateRequest: String,
}


// 6.3.2 Ieee1609Dot2Data
// Ieee1609Dot2Data ::= SEQUENCE {
// protocolVersion Uint8(3),
// content Ieee1609Dot2Content
// }
// This data type is used to contain the other data types in this clause. The fields in the Ieee1609Dot2Data
// have the following meanings:
//  protocolVersion contains the current version of the protocol. The version specified in this
// document is version 3, represented by the integer 3. There are no major or minor version numbers.
//  content contains the content in the form of an Ieee1609Dot2Content.

struct Iee1609Dot2Data {
    protocol_version: u8,
    content: Iee1609Dot2Content,
}

