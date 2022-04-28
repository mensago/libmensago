use std::collections::HashMap;
use eznacl::*;
use crate::base::*;

/// The Keycard interface provides a general way for working with organization and user keycards
pub trait Keycard {
	fn from(data: &str);
	fn is_data_compliant(&self) -> Result<(), MensagoError>;
	fn is_compliant(&self) -> Result<(), MensagoError>;
	fn is_timestamp_valid(&self) -> Result<(), MensagoError>;
	fn is_expired(&self) -> Result<(), MensagoError>;
	//fn get_signature(&self, sigtype: ???) -> Result<(), MensagoError>;
	//fn get_text(&self, signature_level: ???) -> Result<(), MensagoError>;
	fn set_field(&mut self, field_name: &str, field_value: &str) -> Result<(), MensagoError>;
	fn set_fields(&mut self, fields: HashMap<String, String>) -> Result<(), MensagoError>;
	fn set_expiration(&self, numdays: Option<u16>);
	//fn sign(&mut self, signing_key: eznacl::CryptoString, sigtype: ????) -> Result<(), MensagoError>;
	//fn generate_hash(&mut self, algorithm: ??) -> Result<(), MensagoError>;
	fn verify_hash(&self) -> Result<(), MensagoError>;
	//fn verify_signature(&mut self, verify_key: eznacl::CryptoString, sigtype: ????) -> Result<(), MensagoError>;
}

// KeycardBase implements the prts of the Keycard interface common to both keycard types
struct KeycardBase {
	fields: HashMap<String, String>,
	prev_hash: eznacl::CryptoString,
	hash: eznacl::CryptoString,
}

