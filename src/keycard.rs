use std::collections::HashMap;
use eznacl::*;
use crate::base::*;

/// The KeycardEntryBase trait provides methods common to all keycard types
pub trait KeycardEntryBase {

	/// Returns the type of keycard
	fn get_type(&self) -> EntryType;
	
	/// Gets the specified field for an entry
	fn get_field(&self, field_name: &str) -> Result<String, MensagoError>;

	/// Sets an entry field
	fn set_field(&mut self, field_name: &str, field_value: &str) -> Result<(), MensagoError>;

	/// Sets multiple entry fields
	fn set_fields(&mut self, fields: &HashMap<String, String>) -> Result<(), MensagoError>;

	/// Deletes a field from the entry
	fn delete_field(&mut self, field_name: &str) -> Result<(), MensagoError>;
}

/// The KeycardEntry trait provides implementation-specific keycard methods
pub trait KeycardEntry {

	/// Returns false if the data in any of the regular fields is not compliant
	fn is_data_compliant(&self) -> Result<bool, MensagoError>;

	/// Returns false if the entry has any compliance issues, including missing or bad hashes
	/// and/or signatures.
	fn is_compliant(&self) -> Result<bool, MensagoError>;

	/// Sets the expiration date for the entry
	fn set_expiration(&self, numdays: Option<&u16>) -> Result<(), MensagoError>;

	/// Returns true if the entry has exceeded its expiration date
	fn is_expired(&self) -> Result<bool, MensagoError>;
	
	/// Returns the entire text of the entry minus any signatures or hashes
	fn get_text(&self, signature_level: AuthStrType, include_auth: &bool)
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

	/// Returns true if the block has the specified authentication string type
	fn has_authstr(&self, astype: &AuthStrType) -> bool;

	/// Returns the specified authentication string
	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError>;

	/// Sets the specified authentication string to the value passed. NOTE: no validation of the
	/// authentication string is performed by this call. The primary use for this method is to set
	/// the previous hash for the signature block
	fn add_authstr(&mut self, astype: &AuthStrType, astr: &CryptoString) -> Result<(), MensagoError>;

	/// Calculates the hash for the entry text using the specified algorithm. Requirements for this
	/// call vary with the entry implementation. ErrOutOfOrderSignature is returned if a hash is
	/// requested before another required authentication string has been set.
	fn hash(&mut self, entry: &str, algorithm: &str) -> Result<(), MensagoError>;

	/// Creates the requested signature. Requirements for this call vary with the entry
	/// implementation. ErrOutOfOrderSignature is returned if a signature is requested before
	/// another required authentication string has been set. ErrBadValue is returned for a
	/// signature type not used by the specific implementation.
	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_key: &SigningPair)
		-> Result<(), MensagoError>;
	
	/// Verifies the requested signature. ErrBadValue is returned for a signature type not used by
	/// the specific implementation.
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
		
		let strings = vec![entry];

		match astype {
			AuthStrType::User => {
				// Calling the User signature type on an org card indicates a bug in the caller's
				// code
				return Err(MensagoError::ErrBadValue)
			},
			AuthStrType::Custody => {
				/* For the custody signature, we don't need to do anything extra */
			},
			AuthStrType::PrevHash => {
				// This method should never be called with the PrevHash type becuase it makes no
				// sense. Instead, add_authstr() should be called to populate the PrevHash field
				return Err(MensagoError::ErrOutOfOrderSignature)
			},
			AuthStrType::Hash => {
				// This method should never be called with the Hash type because that's what the
				// hash() method is for and is the sign of a bug in the caller's code.
				return Err(MensagoError::ErrOutOfOrderSignature)
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
						return Err(MensagoError::ErrOutOfOrderSignature)
					},
				};
			}
		};

		let totaldata = strings.join("\r\n");
		let signature = signing_pair.sign(totaldata.as_bytes())?;

		self.add_authstr(&AuthStrType::Organization, &signature)
	}

	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature) 
		-> Result<(), MensagoError> {
		
		let strings = vec![entry];

		let sig = match astype {
			AuthStrType::User => {
				// Calling the User signature type on an org card indicates a bug in the caller's
				// code
				return Err(MensagoError::ErrBadValue)
			},
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

// TODO: Implement UserSigBlock

// KeycardBase implements the parts of the Keycard interface common to both keycard types
struct KEntryBase {
	_type: EntryType,
	fields: HashMap<String, String>,
}

impl KEntryBase {

	pub fn init(&mut self, t: &EntryType) {
		self._type = *t;
		self.fields = HashMap::<String, String>::new();
	}
}

impl KeycardEntryBase for KEntryBase {

	fn get_type(&self) -> EntryType {
		self._type
	}
	
	fn get_field(&self, field_name: &str) -> Result<String, MensagoError> {

		if field_name.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}

		match self.fields.get(field_name) {
			Some(v) => {
				Ok(*v)
			},
			None => {
				Err(MensagoError::ErrNotFound)
			}
		}
	}

	fn set_field(&mut self, field_name: &str, field_value: &str) -> Result<(), MensagoError> {

		if field_name.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}

		let _ = self.fields.insert(String::from(field_name), String::from(field_value));		
		Ok(())
	}

	fn set_fields(&mut self, fields: &HashMap<String, String>) -> Result<(), MensagoError> {

		if fields.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}
		
		// I'm sure there's a more compact way to do this, but I can't figure out what it would be.
		// :(
		for (k, v) in fields.iter() {
			let _ = self.fields.insert(*k, *v);
		}
		
		Ok(())
	}

	fn delete_field(&mut self, field_name: &str) -> Result<(), MensagoError> {

		if field_name.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}

		let _ = self.fields.remove(field_name);
		Ok(())
	}
}

