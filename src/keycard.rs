use std::collections::HashMap;
use std::fmt;
use chrono::prelude::*;
use regex::Regex;
use lazy_static::lazy_static;
use eznacl::*;
use crate::base::*;
use crate::types::*;

lazy_static! {
	static ref INDEX_PATTERN: regex::Regex = 
		Regex::new(r"^\d+$")
		.unwrap();
	
	static ref NAME_PATTERN: regex::Regex = 
		Regex::new(r"\w+")
		.unwrap();
	
	static ref LANGUAGE_PATTERN: regex::Regex = 
		Regex::new(r"^[a-zA-Z]{2,3}(,[a-zA-Z]{2,3})*?$")
		.unwrap();
}

/// Enumerated type for all keycard entry fields
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub enum EntryFieldType {
	Index,
	Name,
	WorkspaceID,
	UserID,
	Domain,
	ContactRequestVerificationKey,
	ContactRequestEncryptionKey,
	EncryptionKey,
	VerificationKey,
	TimeToLive,
	Expires,
	Timestamp,
	Language,
	PrimaryVerificationKey,
	SecondaryVerificationKey,
	ContactAdmin,
	ContactAbuse,
	ContactSupport,
}

impl EntryFieldType {

	pub fn from(s: &str) -> Option<EntryFieldType> {

		match s {
			"Index" => Some(EntryFieldType::Index),
			"Name" => Some(EntryFieldType::Name),
			"Workspace-ID" => Some(EntryFieldType::WorkspaceID),
			"User-ID" => Some(EntryFieldType::UserID),
			"Domain" => Some(EntryFieldType::Domain),
			"Contact-Request-Verification-Key" => Some(EntryFieldType::ContactRequestVerificationKey),
			"Contact-Request-Encryption-Key" => Some(EntryFieldType::ContactRequestEncryptionKey),
			"Encryption-Key" => Some(EntryFieldType::EncryptionKey),
			"Verification-Key" => Some(EntryFieldType::VerificationKey),
			"Time-To-Live" => Some(EntryFieldType::TimeToLive),
			"Expires" => Some(EntryFieldType::Expires),
			"Timestamp" => Some(EntryFieldType::Timestamp),
			"Language" => Some(EntryFieldType::Language),
			"Primary-Verification-Key" => Some(EntryFieldType::PrimaryVerificationKey),
			"Secondary-Verification-Key" => Some(EntryFieldType::SecondaryVerificationKey),
			"Contact-Admin" => Some(EntryFieldType::ContactAdmin),
			"Contact-Abuse" => Some(EntryFieldType::ContactAbuse),
			"Contact-Support" => Some(EntryFieldType::ContactSupport),

			_ => None,
		}
	}

	/// Creates a new field instance based on the field type and value given to it. If the data
	/// isn't valid, None is returned.
	pub fn new_field(t: &Self, s: &str) -> Option<Box<dyn VerifiedString>> {

		match t {
			EntryFieldType::Index => IndexField::new(s),
			EntryFieldType::Name => NameField::new(s),
			EntryFieldType::WorkspaceID => RandomID::new(s),
			EntryFieldType::UserID => MAddress::new(s),
			EntryFieldType::Domain => Domain::new(s),
			EntryFieldType::ContactRequestEncryptionKey => CryptoStringField::new(s),
			EntryFieldType::ContactRequestVerificationKey => CryptoStringField::new(s),
			EntryFieldType::EncryptionKey => CryptoStringField::new(s),
			EntryFieldType::VerificationKey => CryptoStringField::new(s),
			EntryFieldType::TimeToLive => TTLField::new(s),
			EntryFieldType::Expires => DateField::new(s),
			EntryFieldType::Timestamp => DateTimeField::new(s),
			EntryFieldType::Language => LanguageField::new(s),
			EntryFieldType::PrimaryVerificationKey => CryptoStringField::new(s),
			EntryFieldType::SecondaryVerificationKey => CryptoStringField::new(s),
			EntryFieldType::ContactAdmin => WAddress::new(s),
			EntryFieldType::ContactAbuse => WAddress::new(s),
			EntryFieldType::ContactSupport => WAddress::new(s),
		}
	}
}

impl fmt::Display for EntryFieldType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			EntryFieldType::Index => write!(f, "Index"),
			EntryFieldType::Name => write!(f, "Name"),
			EntryFieldType::WorkspaceID => write!(f, "Workspace-ID"),
			EntryFieldType::UserID => write!(f, "User-ID"),
			EntryFieldType::Domain => write!(f, "Domain"),
			EntryFieldType::ContactRequestVerificationKey => write!(f, "Contact-Request-Verification-Key"),
			EntryFieldType::ContactRequestEncryptionKey => write!(f, "Contact-Request-Encryption-Key"),
			EntryFieldType::EncryptionKey => write!(f, "Encryption-Key"),
			EntryFieldType::VerificationKey => write!(f, "Verification-Key"),
			EntryFieldType::TimeToLive => write!(f, "Time-To-Live"),
			EntryFieldType::Expires => write!(f, "Expires"),
			EntryFieldType::Timestamp => write!(f, "Timestamp"),
			EntryFieldType::Language => write!(f, "Language"),
			EntryFieldType::PrimaryVerificationKey => write!(f, "Primary-Verification-Key"),
			EntryFieldType::SecondaryVerificationKey => write!(f, "Secondary-Verification-Key"),
			EntryFieldType::ContactAdmin => write!(f, "Contact-Admin"),
			EntryFieldType::ContactAbuse => write!(f, "Contact-Abuse"),
			EntryFieldType::ContactSupport => write!(f, "Contact-Support"),
		}
	}
}

/// The KeycardEntry trait provides implementation-specific keycard methods
pub trait KeycardEntry {
	/// Returns the type of keycard
	fn get_type(&self) -> EntryType;
	
	/// Gets the specified field for an entry
	fn get_field(&self, field: &EntryFieldType) -> Result<String, MensagoError>;

	/// Sets an entry field
	fn set_field(&mut self, field: &EntryFieldType, value: &str) -> Result<(), MensagoError>;

	/// Sets multiple entry fields from a list of type-value mappings
	fn set_fields(&mut self, fields: &Vec<(EntryFieldType, String)>) -> Result<(), MensagoError>;

	/// Sets multiple entry fields from a list of string-string mappings
	fn set_fields_str(&mut self, fields: &Vec<(String, String)>) -> Result<(), MensagoError>;

	/// Deletes a field from the entry
	fn delete_field(&mut self, field: &EntryFieldType) -> Result<(), MensagoError>;

	/// Returns false if the data in any of the regular fields is not compliant
	fn is_data_compliant(&self) -> Result<bool, MensagoError>;

	/// Returns false if the entry has any compliance issues, including missing or bad hashes
	/// and/or signatures.
	fn is_compliant(&self) -> Result<bool, MensagoError>;

	/// Sets the expiration date for the entry
	fn set_expiration(&mut self, numdays: Option<&u16>) -> Result<(), MensagoError>;

	/// Returns true if the entry has exceeded its expiration date
	fn is_expired(&self) -> Result<bool, MensagoError>;
	
	/// Returns the entire text of the entry minus any signatures or hashes
	fn get_text(&self, signature_level: &AuthStrType, include_auth: bool)
		-> Result<String, MensagoError>;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub enum EntryType {
	Organization,
	User
}

impl fmt::Display for EntryType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			EntryType::Organization => write!(f, "Organization"),
			EntryType::User => write!(f, "User"),
		}
	}
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
	fn has_authstr(&self, astype: &AuthStrType) -> Result<bool, MensagoError>;

	/// Returns the specified authentication string
	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError>;

	/// Returns a list of authentication strings in order of their need to appear in a keycard entry
	fn get_text(&self, aslevel: &AuthStrType) -> Result<Vec::<CryptoString>, MensagoError>;

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

	fn astype_to_index(astype: &AuthStrType) -> Result<usize,MensagoError> {

		match astype {
			AuthStrType::User => Err(MensagoError::ErrBadValue),
			AuthStrType::Custody => Ok(0),
			AuthStrType::PrevHash => Ok(1),
			AuthStrType::Hash => Ok(2),
			AuthStrType::Organization => Ok(3),
		}
	}

	fn index_to_astype(index: &usize) -> Result<AuthStrType,MensagoError> {

		match index {
			0 => Ok(AuthStrType::Custody),
			1 => Ok(AuthStrType::PrevHash),
			2 => Ok(AuthStrType::Hash),
			3 => Ok(AuthStrType::Organization),
			_ => Err(MensagoError::ErrBadValue),
		}
	}

	pub fn new() -> OrgSigBlock {
		OrgSigBlock { signatures: [None, None, None, None].clone() }
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

	fn has_authstr(&self, astype: &AuthStrType) -> Result<bool,MensagoError> {
	
		let index = OrgSigBlock::astype_to_index(astype)?;

		match self.signatures[index] {
			Some(_) => Ok(true),
			None => Ok(false)
		}
	}

	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError> {

		let index = OrgSigBlock::astype_to_index(astype)?;

		match &self.signatures[index] {
			Some(v) => Ok(v.clone()),
			None => Err(MensagoError::ErrNotFound)
		}
	}

	fn get_text(&self, aslevel: &AuthStrType) -> Result<Vec::<CryptoString>, MensagoError> {
		
		let mut out = Vec::<CryptoString>::new();
		let lastindex = OrgSigBlock::astype_to_index(aslevel)?;
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

		let index = OrgSigBlock::astype_to_index(astype)?;

		self.signatures[index] = Some(astr.clone());
		
		Ok(())
	}
	
	fn hash(&mut self, entry: &str, algorithm: &str) -> Result<(), MensagoError> {

		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));

		let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody)?;
		match &self.signatures[index] {
			Some(v) => {
				strings.push(v.to_string())
			},
			None => { /* Do nothing if the custody signature doesn't exist */ },
		};
		index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash)?;
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
				let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
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
			}
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
			AuthStrType::User => {
				// Calling the User signature type on an org card indicates a bug in the caller's
				// code
				return Err(MensagoError::ErrBadValue)
			},
			AuthStrType::Custody => {

				let index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
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
				let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::Organization => {
				
				// The org signature on org cards is the final field, so make sure that we have all
				// other hashes and signatures included in the verification data if they exist
				let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
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

				index = OrgSigBlock::astype_to_index(astype)?;
				match &self.signatures[index] {
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
				return if hash == *sig {
					Ok(())
				} else {
					Err(MensagoError::ErrInvalidKeycard)
				}
			}			
			AuthStrType::Organization => {
				let index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
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

// TODO: Implement UserSigBlock

// OrgEntry is an entry for an organizational keycard
struct OrgEntry {
	_type: EntryType,
	fields: HashMap<EntryFieldType, Box<dyn VerifiedString>>,
	sigs: OrgSigBlock,
}


static ORG_REQUIRED_FIELDS: [&EntryFieldType; 7] = [
	&EntryFieldType::Index,
	&EntryFieldType::Name,
	&EntryFieldType::ContactAdmin,
	&EntryFieldType::PrimaryVerificationKey,
	&EntryFieldType::TimeToLive,
	&EntryFieldType::Expires,
	&EntryFieldType::Timestamp,
];

impl OrgEntry {

	pub fn new() -> OrgEntry {
		OrgEntry {
			_type: EntryType::Organization,
			fields: HashMap::<EntryFieldType, Box<dyn VerifiedString>>::new(),
			sigs: OrgSigBlock::new(),
		}
	}
}

impl KeycardEntry for OrgEntry {

	fn get_type(&self) -> EntryType {
		self._type
	}
	
	fn get_field(&self, field: &EntryFieldType) -> Result<String, MensagoError> {

		match self.fields.get(field) {
			Some(v) => {
				Ok(String::from(v.get()))
			},
			None => {
				Err(MensagoError::ErrNotFound)
			}
		}
	}

	fn set_field(&mut self, field: &EntryFieldType, value: &str) -> Result<(), MensagoError> {

		match field {
			EntryFieldType::Index => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Name => { /* Field is OK. Do nothing. */ },
			EntryFieldType::ContactAdmin => { /* Field is OK. Do nothing. */ },
			EntryFieldType::ContactAbuse => { /* Field is OK. Do nothing. */ },
			EntryFieldType::ContactSupport => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Language => { /* Field is OK. Do nothing. */ },
			EntryFieldType::PrimaryVerificationKey => { /* Field is OK. Do nothing. */ },
			EntryFieldType::SecondaryVerificationKey => { /* Field is OK. Do nothing. */ },
			EntryFieldType::TimeToLive => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Expires => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Timestamp => { /* Field is OK. Do nothing. */ },
			_ => {
				return Err(MensagoError::ErrBadValue)
			}
		}

		match EntryFieldType::new_field(field, value) {
			Some(v) => {
				let _ = self.fields.insert(*field, v);
			},
			None => {
				return Err(MensagoError::ErrBadValue)
			}
		}
		Ok(())
	}

	fn set_fields(&mut self, fields: &Vec<(EntryFieldType, String)>) -> Result<(), MensagoError> {

		if fields.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}
		
		// I'm sure there's a more compact way to do this, but I can't figure out what it would be.
		// :(
		for (k, v) in fields.iter() {
			match EntryFieldType::new_field(k, v) {
				Some(v) => {
					let _ = self.fields.insert(*k, v);
				},
				None => {
					return Err(MensagoError::ErrBadValue)
				}
			}
		}
		
		Ok(())
	}

	fn set_fields_str(&mut self, fields: &Vec<(String, String)>) -> Result<(), MensagoError> {

		if fields.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}
		
		for (k, v) in fields.iter() {
			match EntryFieldType::from(k) {
				Some(ft) => {
					match EntryFieldType::new_field(&ft, v) {
						Some(fieldval) => {
							let _ = self.fields.insert(ft, fieldval);
						},
						None => {
							return Err(MensagoError::ErrBadValue)
						}
					}
			
				},
				None => {
					return Err(MensagoError::ErrBadValue)
				}
			};
		}
		
		Ok(())
	}

	fn delete_field(&mut self, field: &EntryFieldType) -> Result<(), MensagoError> {

		let _ = self.fields.remove(field);
		Ok(())
	}

	fn is_data_compliant(&self) -> Result<bool, MensagoError> {

		// Ensure that all required fields are present. Because each field is a ValidatedString, we
		// already know that if the field is present, it's valid, too. :)
		for f in ORG_REQUIRED_FIELDS {
			match self.fields.get(f) {
				Some(_) => { /* do nothing */ },
				None => {
					return Ok(false)
				}
			}
		}

		Ok(true)
	}

	fn is_compliant(&self) -> Result<bool, MensagoError> {

		let status = self.is_data_compliant()?;
		if !status {
			return Ok(status);
		}

		// The Custody signature and the PrevHash field are both required if the entry is not the
		// root entry of the org's keycard.
		let entry_index = match self.fields.get(&EntryFieldType::Index) {
			Some(v) => {
				match v.get().parse::<u32>() {
					Ok(i) => i,
					Err(e) => {
						// We should never be here
						return Err(MensagoError::ErrProgramException(e.to_string()))
					},
				}
			},
			None => {
				return Ok(false)
			}
		};

		if entry_index > 0 {
			match OrgSigBlock::astype_to_index(&AuthStrType::Custody) {
				Ok(_) => { /* Do nothing*/ },
				Err(_) => return Ok(false)
			}
			match OrgSigBlock::astype_to_index(&AuthStrType::PrevHash) {
				Ok(_) => { /* Do nothing*/ },
				Err(_) => return Ok(false)
			}
		}

		match OrgSigBlock::astype_to_index(&AuthStrType::Hash) {
			Ok(_) => { /* Do nothing*/ },
			Err(_) => return Ok(false)
		}

		match OrgSigBlock::astype_to_index(&AuthStrType::Custody) {
			Ok(_) => Ok(true),
			Err(_) => Ok(false)
		}
	}

	fn set_expiration(&mut self, numdays: Option<&u16>) -> Result<(), MensagoError> {

		let count = match numdays {
			Some(v) => {
				// The expiration date may be no longer than 3 years
				if *v > 1095 {
					return Err(MensagoError::ErrBadValue)
				}
				*v
			},
			None => {
				if self._type == EntryType::Organization {
					365
				} else {
					90
				}
			}
		};

		self.set_field(&EntryFieldType::Expires, &count.to_string())?;

		Ok(())
	}

	/// Returns true if the entry has exceeded its expiration date
	fn is_expired(&self) -> Result<bool, MensagoError> {

		// Yes, it would make more sense to simply have a stored value which was already parsed,
		// but the necessary code to do the dynamic dispatch to handle this would probably increase
		// complexity by an order of magnitude. We'll sacrifice a tiny bit of performance for 
		// simplicity.
		let expdate = match self.fields.get(&EntryFieldType::Expires) {
			Some(v) => {
				match NaiveDate::parse_from_str(v.get(), "%Y%m%d") {
					Ok(d) => d,
					Err(e) => {
						// We should never be here
						return Err(MensagoError::ErrProgramException(e.to_string()))
					}
				}
			},
			None => {
				return Err(MensagoError::ErrNotFound)
			}
		};

		let now = Utc::now().date().naive_utc();

		if now > expdate {
			Ok(true)
		} else {
			Ok(false)
		}
	}
	
	/// Returns the entire text of the entry minus any signatures or hashes
	fn get_text(&self, signature_level: &AuthStrType, include_auth: bool)
		-> Result<String, MensagoError> {
		
		let mut lines = Vec::<String>::new();
		
		// First line of an entry must be the type
		lines.push(String::from("Type:")+&self._type.to_string());

		for (k,v) in self.fields.iter() {
			let parts = [k.to_string(), v.get().to_string()];
			lines.push(parts.join(":"));
		}

		if include_auth {
			lines.extend(self.sigs.get_text(signature_level)?
				.iter()
				.map(|x| x.to_string()));
		}

		Ok(lines.join("\r\n"))
	}
}

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

/// A verified type for handling keycard entry indexes
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct IndexField {
	data: String
}

impl VerifiedString for IndexField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "IndexField"
	}
}

impl fmt::Display for IndexField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl IndexField {

	/// Creates a new IndexField from a string or None if not valid
	pub fn from(s: &str) -> Option<IndexField> {

		if !INDEX_PATTERN.is_match(s) {
			return None
		}

		Some(IndexField{ data:String::from(s) })
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}

/// A verified type for handling keycard name fields
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct NameField {
	data: String
}

impl VerifiedString for NameField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "NameField"
	}
}

impl fmt::Display for NameField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl NameField {

	pub fn from(s: &str) -> Option<NameField> {

		// Names must meet 3 conditions:
		// 1-64 Unicode codepoints
		// At least 1 printable character
		// no leading or trailing whitespace

		let trimmed = s.trim();

		if !NAME_PATTERN.is_match(trimmed) {
			return None
		}

		if trimmed.len() > 0 && trimmed.len() < 65 {
			Some(NameField{ data:String::from(trimmed) })
		} else {
			None
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}

/// A verified type for handling keycard workspace ID fields
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct WIDField {
	data: String
}

impl VerifiedString for WIDField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "WIDField"
	}
}

impl fmt::Display for WIDField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl WIDField {

	pub fn from(s: &str) -> Option<WIDField> {

		// A workspace ID is literally just a RandomID + / + domain, so we'll just
		// split the field and check the parts individually
		let trimmed = s.trim();
		let parts: Vec<&str> = trimmed.split('/').collect();
		if parts.len() != 2 {
			return None
		}

		if !RANDOMID_PATTERN.is_match(parts[0]) || !DOMAIN_PATTERN.is_match(parts[1]) {
			None
		} else {
			Some(WIDField{ data: String::from(trimmed) })
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}

/// A verified type for handling keycard Time-To-Live fields
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct TTLField {
	data: String
}

impl VerifiedString for TTLField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "TTLField"
	}
}

impl fmt::Display for TTLField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl TTLField {

	pub fn from(s: &str) -> Option<TTLField> {

		let trimmed = s.trim();
		
		// The TTL is just a number from 1-30, so the Index field's regex will do nicely here. :)
		if !INDEX_PATTERN.is_match(s) {
			return None
		}

		match trimmed.parse::<u8>() {
			Err(e) => None,
			Ok(v) => {
				if v < 1 || v > 30 {
					None
				} else {
					Some(TTLField{ data: String::from(trimmed) })
				}
			}
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}

/// A verified type for handling date fields in keycards
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct DateField {
	data: String
}

impl VerifiedString for DateField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "DateField"
	}
}

impl fmt::Display for DateField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl DateField {

	pub fn generate() -> DateField {

		let utc: Date<Utc> = Utc::now().date();
		let formatted = utc.format("%Y%m%d");

		DateField{ data: String::from(formatted.to_string()) }
	}
	
	pub fn from(s: &str) -> Option<DateField> {

		let trimmed = s.trim();

		match chrono::NaiveDate::parse_from_str(trimmed, "%Y%m%d") {
			Ok(v) => {
				Some(DateField { data: String::from(trimmed) })
			},
			Err(_) => {
				 None
			},
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}

/// A verified type for handling timestamp fields in keycards
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct DateTimeField {
	data: String,
}

impl VerifiedString for DateTimeField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "DateTimeField"
	}
}

impl fmt::Display for DateTimeField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl DateTimeField {

	pub fn generate() -> DateTimeField {

		let utc: DateTime<Utc> = Utc::now();
		let formatted = utc.format("%Y%m%dT%H%M%SZ");

		DateTimeField { data: String::from(formatted.to_string()) }
	}
	
	pub fn from(s: &str) -> Option<DateTimeField> {

		let trimmed = s.trim();

		match chrono::NaiveDateTime::parse_from_str(trimmed, "%Y%m%dT%H%M%SZ") {
			Ok(v) => {
				Some(DateTimeField { data: String::from(trimmed) })
			},
			Err(_) => {
				 None
			},
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}

/// A verified type for handling the language field in org keycards
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct LanguageField {
	data: String
}

impl VerifiedString for LanguageField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "LanguageField"
	}
}

impl fmt::Display for LanguageField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl LanguageField {

	pub fn from(s: &str) -> Option<LanguageField> {

		let trimmed = s.trim();
		
		if !LANGUAGE_PATTERN.is_match(s) {
			return None
		}

		match trimmed.parse::<u8>() {
			Err(e) => None,
			Ok(v) => {
				if v < 1 || v > 30 {
					None
				} else {
					Some(LanguageField{ data: String::from(trimmed) })
				}
			}
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}


/// A verified type for handling the language field in org keycards
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct CryptoStringField {
	data: String
}

impl VerifiedString for CryptoStringField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "CryptoStringField"
	}
}

impl fmt::Display for CryptoStringField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl CryptoStringField {

	pub fn from(s: &str) -> Option<CryptoStringField> {

		match CryptoString::from(s) {
			Some(v) => {
				Some(CryptoStringField { data: v.to_string() })
			},
			None => return None
		}
	}

	/// Creates a heap-allocated version of the field from a string or None if not valid
	pub fn new(s: &str) -> Option<Box<dyn VerifiedString>> {

		match Self::from(s) {
			Some(v) => Some(Box::<Self>::new(v)),
			None => None
		}
	}
}


#[cfg(test)]
mod tests {
	use crate::*;
	use std::env;
	use std::fs;
	use std::path::PathBuf;
	use std::str::FromStr;

	// Sets up the path to contain the profile tests
	fn setup_test(name: &str) -> PathBuf {
		if name.len() < 1 {
			panic!("Invalid name {} in setup_test", name);
		}
		let args: Vec<String> = env::args().collect();
		let test_path = PathBuf::from_str(&args[0]).unwrap();
		let mut test_path = test_path.parent().unwrap().to_path_buf();
		test_path.push("testfiles");
		test_path.push(name);

		if test_path.exists() {
			fs::remove_dir_all(&test_path).unwrap();
		}
		fs::create_dir_all(&test_path).unwrap();

		test_path
	}

	#[test]
	fn orgentry_set_get_field() -> Result<(), MensagoError> {
		
		let mut entry = crate::keycard::OrgEntry::new();

		// Try setting a bad field value
		match entry.set_field(&EntryFieldType::Domain, "/123*") {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_field passed an invalid value")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		// Try setting a field which isn't used for organizations
		match entry.set_field(&EntryFieldType::UserID, "csimons") {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_field allowed an invalid entry type")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		// Try setting a good field value
		match entry.set_field(&EntryFieldType::Name, "Corbin Simons") {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_field failed: {}", e.to_string())))
			}
		}

		// Try getting a field which doesn't exist
		match entry.get_field(&EntryFieldType::Domain) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_get_field passed a nonexistent field")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		// Try getting a field, expecting success here
		match entry.get_field(&EntryFieldType::Name) {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_get_field failed: {}", e.to_string())))
			}
		}

		Ok(())
	}

	#[test]
	fn orgentry_set_fields() -> Result<(), MensagoError> {
		
		let mut entry = crate::keycard::OrgEntry::new();

		let mut testdata = vec![
			(EntryFieldType::Name, String::from("Example, Inc.")),
			(EntryFieldType::ContactAdmin, String::from("example.com")),
		];
		
		match entry.set_fields(&testdata) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields passed an invalid value")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		testdata = vec![
			(EntryFieldType::Name, String::from("Example, Inc.")),
			(EntryFieldType::ContactAdmin, String::from("11111111-1111-1111-1111-111111111111/example.com")),
		];
		match entry.set_fields(&testdata) {
			Ok(_) => Ok(()),
			Err(e) => {
				Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields failed: {}", e.to_string())))
			}
		}
	}

	#[test]
	fn orgentry_set_fields_str() -> Result<(), MensagoError> {
		
		let mut entry = crate::keycard::OrgEntry::new();

		let mut testdata = vec![
			(String::from("Name"), String::from("Example, Inc.")),
			(String::from("contactAdmin"),
				String::from("11111111-1111-1111-1111-111111111111/example.com")),
		];
		
		match entry.set_fields_str(&testdata) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields_str passed an invalid key")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		testdata = vec![
			(String::from("Name"), String::from("Example, Inc.")),
			(String::from("Contact-Admin"),
				String::from("11111111-1111-1111-1111-111111111111/example.com")),
		];
		match entry.set_fields_str(&testdata) {
			Ok(_) => Ok(()),
			Err(e) => {
				Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields_str failed: {}", e.to_string())))
			}
		}
	}

	#[test]
	fn orgentry_delete_field() -> Result<(), MensagoError> {
		
		let mut entry = crate::keycard::OrgEntry::new();

		// Setup
		match entry.set_field(&EntryFieldType::Name, "Corbin Simons") {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field failed: {}", e.to_string())))
			}
		}

		// Make sure we can get the field
		match entry.get_field(&EntryFieldType::Name) {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field failed to get field: {}", e.to_string())))
			}
		}

		// Remove it
		match entry.delete_field(&EntryFieldType::Name) {
			Ok(_) => {
				/* Test condition passes. Do nothing. */
			},
			Err(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field failed to delete a field")))
			}
		}
		
		// Make sure the field doesn't exist anymore
		match entry.get_field(&EntryFieldType::Name) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field didn't actually delete the test field")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		Ok(())
	}
}
