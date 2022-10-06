use crate::base::*;
use std::fmt;
use std::str::FromStr;

/// KeyType defines the cryptographic purpose for a key, as in if it is used for symmetric
/// encryption, asymmetric encryption, or digital signatures
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum KeyType {
    SymEncryptionKey,
    AsymEncryptionKey,
    SigningKey,
}

/// KeyCategory defines the general usage of a key.
/// - ConReqEncryption: Contact request encryption/decryption
/// - ConReqSigning: Contact request signing/verification
/// - Encryption: General-purpose encryption/decryption
/// - Signing: General-purpose encryption/decryption
/// - Folder: server-side path name storage encryption
/// - PrimarySigning: organization primary signing/verification
/// - SecondarySigning: organization secondary signing/verification
/// - Storage: server-side file storage
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum KeyCategory {
    ConReqEncryption,
    ConReqSigning,
    Encryption,
    Signing,
    Folder,
    PrimarySigning,
    SecondarySigning,
    Storage,
}

impl fmt::Display for KeyCategory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeyCategory::ConReqEncryption => write!(f, "crencryption"),
            KeyCategory::ConReqSigning => write!(f, "crsigning"),
            KeyCategory::Encryption => write!(f, "encryption"),
            KeyCategory::Signing => write!(f, "signing"),
            KeyCategory::Folder => write!(f, "folder"),
            KeyCategory::PrimarySigning => write!(f, "orgsigning"),
            KeyCategory::SecondarySigning => write!(f, "altorgsigning"),
            KeyCategory::Storage => write!(f, "storage"),
        }
    }
}

impl FromStr for KeyCategory {
    type Err = ();

    fn from_str(input: &str) -> Result<KeyCategory, Self::Err> {
        match input.to_lowercase().as_str() {
            "crencryption" => Ok(KeyCategory::ConReqEncryption),
            "crsigning" => Ok(KeyCategory::ConReqSigning),
            "encryption" => Ok(KeyCategory::Encryption),
            "signing" => Ok(KeyCategory::Signing),
            "folder" => Ok(KeyCategory::Folder),
            "orgsigning" => Ok(KeyCategory::PrimarySigning),
            "altorgsigning" => Ok(KeyCategory::SecondarySigning),
            "storage" => Ok(KeyCategory::Storage),
            _ => Err(()),
        }
    }
}

impl std::convert::TryFrom<&str> for KeyCategory {
    type Error = MensagoError;
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        match input.to_lowercase().as_str() {
            "crencryption" => Ok(KeyCategory::ConReqEncryption),
            "crsigning" => Ok(KeyCategory::ConReqSigning),
            "encryption" => Ok(KeyCategory::Encryption),
            "signing" => Ok(KeyCategory::Signing),
            "folder" => Ok(KeyCategory::Folder),
            "orgsigning" => Ok(KeyCategory::PrimarySigning),
            "altorgsigning" => Ok(KeyCategory::SecondarySigning),
            "storage" => Ok(KeyCategory::Storage),
            _ => Err(MensagoError::ErrBadValue),
        }
    }
}
