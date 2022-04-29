use std::collections::HashMap;
use eznacl::*;
use crate::base::*;

/// The Keycard interface provides a general way for working with organization and user keycards
pub trait KeycardEntry {
	fn get_type(&self) -> EntryType;
	
	fn is_data_compliant(&self) -> Result<(), MensagoError>;
	fn is_compliant(&self) -> Result<(), MensagoError>;
	fn is_expired(&self) -> Result<(), MensagoError>;
	
	fn get_field(&self, field_name: &str) -> Result<String, MensagoError>;
	fn set_field(&mut self, field_name: &str, field_value: &str) -> Result<(), MensagoError>;
	fn set_fields(&mut self, fields: HashMap<String, String>) -> Result<(), MensagoError>;
	fn set_expiration(&self, numdays: Option<u16>);
	
	fn get_text(&self, signature_level: AuthStrType, include_auth: &bool)
		-> Result<(), MensagoError>;
	
	fn has_authstr(&self, astype: &AuthStrType) -> bool;
	fn get_authstr(&self, astype: AuthStrType) -> Result<(), MensagoError>;
	fn sign(&mut self, signing_key: CryptoString, astype: AuthStrType) -> Result<(), MensagoError>;
	fn verify(&mut self, verify_key: eznacl::CryptoString, astype: AuthStrType)
		-> Result<(), MensagoError>;
}

pub enum EntryType {
	Organization,
	User
}

/// The AuthStr type is used to specify authentication strings used in keycard entries. These can
/// either be cryptographic hashes or digital signatures.
pub enum AuthStrType {
	Custody,
	PrevHash,
	Hash,
	Organization,
	User
}

// SignatureBlock abstracts away the logic for handling signatures for keycard entries
trait SignatureBlock {
	fn has_authstr(&self, astype: &AuthStrType) -> bool;
	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError>;
	fn add_authstr(&mut self, astype: &AuthStrType, astr: &CryptoString) -> Result<(), MensagoError>;
	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_key: CryptoString);
	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: CryptoString);
}

struct OrgSigBlock {
	signatures: [Option<CryptoString>; 4]
}

// KeycardBase implements the prts of the Keycard interface common to both keycard types
struct KeycardBase {
	_type: EntryType,
	fields: HashMap<String, String>,
	sigs: dyn SignatureBlock,
}

impl KeycardBase {

}

