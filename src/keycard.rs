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
	fn set_fields(&mut self, fields: &HashMap<String, String>) -> Result<(), MensagoError>;
	fn set_expiration(&self, numdays: Option<&u16>);
	
	fn get_text(&self, signature_level: AuthStrType, include_auth: &bool)
		-> Result<(), MensagoError>;
	
	fn has_authstr(&self, astype: &AuthStrType) -> bool;
	fn get_authstr(&self, astype: &AuthStrType) -> Result<(), MensagoError>;
	fn sign(&mut self, astype: &AuthStrType, signing_pair: &SigningPair) -> Result<(), MensagoError>;
	fn verify(&mut self, astype: &AuthStrType, verify_key: &dyn VerifySignature)
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
	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_key: &SigningPair)
		-> Result<(), MensagoError>;
	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature)
		-> Result<(), MensagoError>;
}

#[derive(Debug)]
struct OrgSigBlock {
	signatures: [Option<CryptoString>; 4]
}

impl OrgSigBlock {

	fn astype_to_index(astype: &AuthStrType) -> usize {

		match astype {
			// 0 is invalid for the OrgSigBlock type
			User => 0,
			Custody => 1,
			PrevHash => 2,
			Hash => 3,
			Organization => 4,
		}
	}
}

impl SignatureBlock for OrgSigBlock {

	fn has_authstr(&self, astype: &AuthStrType) -> bool {
	
		let index = OrgSigBlock::astype_to_index(astype);
		if index == 0 {
			return false
		}

		match self.signatures[index-1] {
			Some(_) => true,
			None => false
		}
	}

	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError> {

		let index = OrgSigBlock::astype_to_index(astype);
		if index == 0 {
			return Err(MensagoError::ErrBadValue)
		}

		match self.signatures[index-1] {
			Some(v) => Ok(v),
			None => Err(MensagoError::ErrNotFound)
		}
	}

	fn add_authstr(&mut self, astype: &AuthStrType, astr: &CryptoString)
		-> Result<(), MensagoError> {

		let index = OrgSigBlock::astype_to_index(astype);
		if index == 0 {
			return Err(MensagoError::ErrBadValue)
		}

		self.signatures[index-1] = Some(*astr);
		
		Ok(())
	}

	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_pair: &SigningPair)
		-> Result<(), MensagoError> {

		// TODO: Implement OrgSigBlock::sign()

		return Err(MensagoError::ErrUnimplemented)
	}
	// fn sign(&mut self, signing_pair: &SigningPair, astype: &AuthStrType) -> Result<(), MensagoError>;

	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature) 
		-> Result<(), MensagoError> {
		
		let strings = vec![entry];

		let sig = match astype {
			AuthStrType::Custody => {
				match self.signatures[OrgSigBlock::astype_to_index(astype)] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			}
		};
		
		let totaldata = strings.join("\r\n");
		
		if verify_key.verify(totaldata.as_bytes(), &sig)? {
			Ok(())
		} else {
			Err(MensagoError::ErrInvalidKeycard)
		}
	}
}

// KeycardBase implements the prts of the Keycard interface common to both keycard types
struct KeycardBase {
	_type: EntryType,
	fields: HashMap<String, String>,
	sigs: dyn SignatureBlock,
}

impl KeycardBase {

}

