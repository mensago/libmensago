use crate::keycard::*;
use std::collections::HashMap;
use chrono::prelude::*;
use chrono::{NaiveDate, Duration};
use eznacl::*;
use crate::base::*;
use crate::keycard::*;
use crate::types::*;


static USER_FIELDS: [&EntryFieldType; 12] = [
	&EntryFieldType::Index,
	&EntryFieldType::Name,
	&EntryFieldType::WorkspaceID,
	&EntryFieldType::UserID,
	&EntryFieldType::Domain,
	&EntryFieldType::ContactRequestVerificationKey,
	&EntryFieldType::ContactRequestEncryptionKey,
	&EntryFieldType::EncryptionKey,
	&EntryFieldType::VerificationKey,
	&EntryFieldType::TimeToLive,
	&EntryFieldType::Expires,
	&EntryFieldType::Timestamp,
];

static USER_REQUIRED_FIELDS: [&EntryFieldType; 10] = [
	&EntryFieldType::Index,
	&EntryFieldType::WorkspaceID,
	&EntryFieldType::Domain,
	&EntryFieldType::ContactRequestVerificationKey,
	&EntryFieldType::ContactRequestEncryptionKey,
	&EntryFieldType::EncryptionKey,
	&EntryFieldType::VerificationKey,
	&EntryFieldType::TimeToLive,
	&EntryFieldType::Expires,
	&EntryFieldType::Timestamp,
];

#[derive(Debug)]
pub struct UserSigBlock {
	signatures: [Option<CryptoString>; 5]
}

impl UserSigBlock {

	fn astype_to_index(astype: &AuthStrType) -> Result<usize,MensagoError> {

		match astype {
			AuthStrType::User => Err(MensagoError::ErrBadValue),
			AuthStrType::Custody => Ok(0),
			AuthStrType::PrevHash => Ok(1),
			AuthStrType::Hash => Ok(2),
			AuthStrType::Organization => Ok(3),
			AuthStrType::User => Ok(4),
		}
	}

	pub fn new() -> UserSigBlock {
		UserSigBlock { signatures: [None, None, None, None, None].clone() }
	}
}

/// The SignatureBlock implementation for UserSigBlock. This provides the specific handling for
/// organizational signatures, which require signatures and hashes in the following order:
/// 
/// - Custody Signature, required for all entries except a keycard's root entry
/// - Previous Hash, required for all entries
/// - Hash, required for all entries
/// - Organization Signature, required for all entries
/// - User Signature, required for all entries
/// 
/// Note that explicitly calling verify() with the Hash type isn't required because it is 
/// automatically verified when the organizational signature is verified.
impl SignatureBlock for UserSigBlock {

	fn has_authstr(&self, astype: &AuthStrType) -> Result<bool,MensagoError> {
	
		let index = UserSigBlock::astype_to_index(astype)?;

		match self.signatures[index] {
			Some(_) => Ok(true),
			None => Ok(false)
		}
	}

	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError> {

		let index = UserSigBlock::astype_to_index(astype)?;

		match &self.signatures[index] {
			Some(v) => Ok(v.clone()),
			None => Err(MensagoError::ErrNotFound)
		}
	}

	fn get_text(&self, aslevel: &AuthStrType) -> Result<Vec::<CryptoString>, MensagoError> {
		
		let mut out = Vec::<CryptoString>::new();
		let lastindex = UserSigBlock::astype_to_index(aslevel)?;
		for item in self.signatures.iter().enumerate() {
			
			if item.0 > lastindex {
				break
			}
			
			match item.1 {
				Some(v) => out.push(v.clone()),
				None => { /* Do nothing */ },
			};
		}
		
		Ok(out)
	}

	fn add_authstr(&mut self, astype: &AuthStrType, astr: &CryptoString)
		-> Result<(), MensagoError> {

		let index = UserSigBlock::astype_to_index(astype)?;

		self.signatures[index] = Some(astr.clone());
		
		Ok(())
	}
	
	fn hash(&mut self, entry: &str, algorithm: &str) -> Result<(), MensagoError> {

		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));

		let mut index = UserSigBlock::astype_to_index(&AuthStrType::Custody)?;
		match &self.signatures[index] {
			Some(v) => {
				strings.push(v.to_string())
			},
			None => { /* Do nothing if the custody signature doesn't exist */ },
		};
		index = UserSigBlock::astype_to_index(&AuthStrType::Organization)?;
		match &self.signatures[index] {
			Some(v) => {
				strings.push(v.to_string())
			},
			None => {
				// A User keycard has more required signatures than an Organization keycard, 
				// including the organization's signature 
				return Err(MensagoError::ErrOutOfOrderSignature)
			},
		};
		index = UserSigBlock::astype_to_index(&AuthStrType::PrevHash)?;
		match &self.signatures[index] {
			Some(v) => {
				strings.push(v.to_string())
			},
			None => { /* Not a big deal if the previous hash field doesn't exist */ },
		};

		let totaldata = strings.join("\r\n");
		
		let hash = get_hash(algorithm, totaldata.as_bytes())?;
		self.add_authstr(&AuthStrType::Hash, &hash)
	}

	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_pair: &SigningPair)
		-> Result<(), MensagoError> {
		
		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));

		match astype {
			AuthStrType::Custody => {
				/* For the custody signature, we don't need to do anything extra */
			},
			AuthStrType::Organization => {
				let index = UserSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
			}
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
			AuthStrType::User => {
				// The User Signature field is the final signature and all required fields,
				// which is defined as everything except the Custody signature, must be in
				// place before the user signature can be applied
				let mut index = UserSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the Custody signature doesn't exist. */ },
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { return Err(MensagoError::ErrOutOfOrderSignature) },
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrOutOfOrderSignature)
					},
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::User).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { 
						return Err(MensagoError::ErrOutOfOrderSignature)
					},
				};
			},
		};

		let totaldata = strings.join("\r\n");
		let signature = signing_pair.sign(totaldata.as_bytes())?;

		self.add_authstr(&AuthStrType::Organization, &signature)
	}

	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature) 
		-> Result<(), MensagoError> {
		
		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));
	
		let sig = match astype {
			AuthStrType::Custody => {

				let index = UserSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::Organization => {
				
				let mut index = UserSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = UserSigBlock::astype_to_index(astype)?;
				match &self.signatures[index] {
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
				let mut index = UserSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::Organization).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => return Err(MensagoError::ErrNotFound),
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::User => {
				let mut index = UserSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::Organization).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => return Err(MensagoError::ErrNotFound),
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = UserSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				index = UserSigBlock::astype_to_index(astype)?;
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
		};
		
		let totaldata = strings.join("\r\n");
		
		// Verify the Hash field when verification of the Hash or Organization fields is requested
		match *astype {
			AuthStrType::Organization => {
				let index = UserSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				let cardhash = match &self.signatures[index] {
					Some(v) => v,
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				let hash = get_hash(cardhash.prefix(), totaldata.as_bytes())?;
				if hash == *cardhash {
					/* Continue on to signature verification */
				} else {
					return Err(MensagoError::ErrInvalidKeycard)
				}
			},
			AuthStrType::Hash => {
				let hash = get_hash(sig.prefix(), totaldata.as_bytes())?;
				return if hash == *sig {
					Ok(())
				} else {
					Err(MensagoError::ErrInvalidKeycard)
				}
			}			
			AuthStrType::User => {
				let index = UserSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				let cardhash = match &self.signatures[index] {
					Some(v) => v,
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				let hash = get_hash(cardhash.prefix(), totaldata.as_bytes())?;
				if hash == *cardhash {
					/* Continue on to signature verification */
				} else {
					return Err(MensagoError::ErrInvalidKeycard)
				}
			},
			_ => { /* Do nothing for the other types */},
		}

		if verify_key.verify(totaldata.as_bytes(), &sig)? {
			Ok(())
		} else {
			Err(MensagoError::ErrInvalidKeycard)
		}
	}
}
