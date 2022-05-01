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

#[derive(Debug, PartialEq, PartialOrd)]
pub enum EntryType {
	Organization,
	User
}

/// The AuthStr type is used to specify authentication strings used in keycard entries. These can
/// either be cryptographic hashes or digital signatures.
#[derive(Debug, PartialEq, PartialOrd)]
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
	fn hash(&mut self, entry: &str, algorithm: &str) -> Result<(), MensagoError>;
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

/// The SignatureBlock implementation for OrgSigBlock. This provides the specific handling for
/// organizational signatures, which require signatures and hashes in the following order:
/// 
/// - Custody Signature, required for all entries except a keycard's root entry
/// - Previous Hash, required for all entries except an organization's root keycard entry
/// - Hash, required for all entries
/// - Organization Signature, required for all entries
/// 
/// Note that explicitly calling verify() with the Hash type isn't required because it is 
/// automatically verified when the organizational signature is verified.
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
	
	fn hash(&mut self, entry: &str, algorithm: &str) -> Result<(), MensagoError> {

		let strings = vec![entry];
		match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::Custody)] {
			Some(v) => {
				strings.push(&v.to_string())
			},
			None => { /* Do nothing if the custody signature doesn't exist */ },
		};
		match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::PrevHash)] {
			Some(v) => {
				strings.push(&v.to_string())
			},
			None => { /* Not a big deal if the previous hash field doesn't exist */ },
		};

		let totaldata = strings.join("\r\n");
		
		let hash = get_hash(algorithm, totaldata.as_bytes())?;
		self.add_authstr(&AuthStrType::Hash, &hash)
	}

	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_pair: &SigningPair)
		-> Result<(), MensagoError> {

		// TODO: Implement OrgSigBlock::sign()

		return Err(MensagoError::ErrUnimplemented)
	}

	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature) 
		-> Result<(), MensagoError> {
		
		let strings = vec![entry];

		let sig = match astype {
			AuthStrType::Custody => {

				match self.signatures[OrgSigBlock::astype_to_index(astype)] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::PrevHash => {

				// It's silly to try to verify the previous hash because there's nothing to verify,
				// but if someone accidentally calls verify() with this type, it's not hurting
				// anything, so we'll just return Ok.
				return Ok(())
			},
			AuthStrType::Hash => {

				// Calling verify() with the Hash type isn't necessary because the hash is also
				// verified when the organizational signature is verified, but if someone really
				// wants to do this, we'll humor them. ;)
				
				// The Hash field includes the Custody Signature and PrevHash fields if present
				match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::Custody)] {
					Some(v) => {
						strings.push(&v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::PrevHash)] {
					Some(v) => {
						strings.push(&v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};

				match self.signatures[OrgSigBlock::astype_to_index(astype)] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::Organization => {
				
				// The org signature on org cards is the final field, so make sure that we have all
				// other hashes and signatures included in the verification data if they exist
				match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::Custody)] {
					Some(v) => {
						strings.push(&v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::PrevHash)] {
					Some(v) => {
						strings.push(&v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				match self.signatures[OrgSigBlock::astype_to_index(&AuthStrType::Hash)] {
					Some(v) => {
						strings.push(&v.to_string())
					},
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				match self.signatures[OrgSigBlock::astype_to_index(astype)] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
		};
		
		let totaldata = strings.join("\r\n");
		
		// Verify the Hash field when verification of the Hash or Organization fields is requested
		match *astype {
			AuthStrType::Hash => {
				let hash = get_hash(sig.prefix(), totaldata.as_bytes())?;
				return if hash == sig {
					Ok(())
				} else {
					Err(MensagoError::ErrInvalidKeycard)
				}
			}			
			AuthStrType::Organization => {
				let cardhash = match self.signatures[
						OrgSigBlock::astype_to_index(&AuthStrType::Hash)] {
					Some(v) => v,
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				let hash = get_hash(cardhash.prefix(), totaldata.as_bytes())?;
				if hash == cardhash {
					/* Continue on to signature verification */
				} else {
					return Err(MensagoError::ErrInvalidKeycard)
				}
			}			
		}

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

