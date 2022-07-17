use std::fmt;

/// KeyType defines the cryptographic purpose for a key, as in if it is used for symmetric
/// encryption, asymmetric encryption, or digital signatures
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum KeyType {
	SymEncryptionKey,
	AsymEncryptionKey,
	SigningKey
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

impl KeyCategory {
	pub fn from_str(from: &str) -> Option<KeyCategory> {
		let squashed = from.to_lowercase();
		match squashed.as_str() {
			"crencryption" => Some(KeyCategory::ConReqEncryption),
			"crsigning" => Some(KeyCategory::ConReqSigning),
			"encryption" => Some(KeyCategory::Encryption),
			"signing" => Some(KeyCategory::Signing),
			"folder" => Some(KeyCategory::Folder),
			"orgsigning" => Some(KeyCategory::PrimarySigning),
			"altorgsigning" => Some(KeyCategory::SecondarySigning),
			"storage" => Some(KeyCategory::Storage),
			_ => None,
		}
	}
}
