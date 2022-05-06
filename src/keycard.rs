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
			"WorkspaceID" => Some(EntryFieldType::WorkspaceID),
			"UserID" => Some(EntryFieldType::UserID),
			"Domain" => Some(EntryFieldType::Domain),
			"ContactRequestVerificationKey" => Some(EntryFieldType::ContactRequestVerificationKey),
			"ContactRequestEncryptionKey" => Some(EntryFieldType::ContactRequestEncryptionKey),
			"EncryptionKey" => Some(EntryFieldType::EncryptionKey),
			"VerificationKey" => Some(EntryFieldType::VerificationKey),
			"TimeToLive" => Some(EntryFieldType::TimeToLive),
			"Expires" => Some(EntryFieldType::Expires),
			"Timestamp" => Some(EntryFieldType::Timestamp),
			"Language" => Some(EntryFieldType::Language),
			"PrimaryVerificationKey" => Some(EntryFieldType::PrimaryVerificationKey),
			"SecondaryVerificationKey" => Some(EntryFieldType::SecondaryVerificationKey),
			"ContactAdmin" => Some(EntryFieldType::ContactAdmin),
			"ContactAbuse" => Some(EntryFieldType::ContactAbuse),
			"ContactSupport" => Some(EntryFieldType::ContactSupport),

			_ => None,
		}
	}
}

impl fmt::Display for EntryFieldType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			EntryFieldType::Index => write!(f, "Index"),
			EntryFieldType::Name => write!(f, "Name"),
			EntryFieldType::WorkspaceID => write!(f, "WorkspaceID"),
			EntryFieldType::UserID => write!(f, "UserID"),
			EntryFieldType::Domain => write!(f, "Domain"),
			EntryFieldType::ContactRequestVerificationKey => write!(f, "ContactRequestVerificationKey"),
			EntryFieldType::ContactRequestEncryptionKey => write!(f, "ContactRequestEncryptionKey"),
			EntryFieldType::EncryptionKey => write!(f, "EncryptionKey"),
			EntryFieldType::VerificationKey => write!(f, "VerificationKey"),
			EntryFieldType::TimeToLive => write!(f, "TimeToLive"),
			EntryFieldType::Expires => write!(f, "Expires"),
			EntryFieldType::Timestamp => write!(f, "Timestamp"),
			EntryFieldType::Language => write!(f, "Language"),
			EntryFieldType::PrimaryVerificationKey => write!(f, "PrimaryVerificationKey"),
			EntryFieldType::SecondaryVerificationKey => write!(f, "SecondaryVerificationKey"),
			EntryFieldType::ContactAdmin => write!(f, "ContactAdmin"),
			EntryFieldType::ContactAbuse => write!(f, "ContactAbuse"),
			EntryFieldType::ContactSupport => write!(f, "ContactSupport"),
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

// OrgEntry is an entry for an organizational keycard
struct OrgEntry {
	_type: EntryType,
	fields: HashMap<EntryFieldType, String>,
}


static org_field_names: [&str; 11] = [
	"Index",
	"Name",
	"Contact-Admin",
	"Contact-Abuse",
	"Contact-Support",
	"Language",
	"Primary-Verification-Key",
	"Secondary-Verification-Key",
	"Time-To-Live",
	"Expires",
	"Timestamp",
];

static org_required_fields: [&str; 7] = [
	"Index",
	"Name",
	"Contact-Admin",
	"Primary-Verification-Key",
	"Time-To-Live",
	"Expires",
	"Timestamp",
];

impl OrgEntry {

	pub fn new(&mut self) {
		self._type = EntryType::Organization;
		self.fields = HashMap::<EntryFieldType, String>::new();
	}
}

impl KeycardEntry for OrgEntry {

	fn get_type(&self) -> EntryType {
		self._type
	}
	
	fn get_field(&self, field: &EntryFieldType) -> Result<String, MensagoError> {

		match self.fields.get(field) {
			Some(v) => {
				Ok(*v)
			},
			None => {
				Err(MensagoError::ErrNotFound)
			}
		}
	}

	fn set_field(&mut self, field: &EntryFieldType, value: &str) -> Result<(), MensagoError> {

		let _ = self.fields.insert(*field, String::from(value));
		Ok(())
	}

	fn set_fields(&mut self, fields: &Vec<(EntryFieldType, String)>) -> Result<(), MensagoError> {

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

	fn set_fields_str(&mut self, fields: &Vec<(String, String)>) -> Result<(), MensagoError> {

		if fields.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}
		
		for (k, v) in fields.iter() {
			let field = match EntryFieldType::from(k) {
				Some(v) => v,
				None => {
					return Err(MensagoError::ErrBadValue)
				}
			};
			let _ = self.fields.insert(field, *v);
		}
		
		Ok(())
	}

	fn delete_field(&mut self, field: &EntryFieldType) -> Result<(), MensagoError> {

		let _ = self.fields.remove(field);
		Ok(())
	}

	fn is_data_compliant(&self) -> Result<bool, MensagoError> {

		// TODO: Implement OrgEntry::is_data_compliant()

		Err(MensagoError::ErrUnimplemented)
	}

	fn is_compliant(&self) -> Result<bool, MensagoError> {

		// TODO: Implement OrgEntry::is_compliant()

		Err(MensagoError::ErrUnimplemented)
	}

	fn set_expiration(&self, numdays: Option<&u16>) -> Result<(), MensagoError> {

		// TODO: Implement OrgEntry::set_expiration()


		Err(MensagoError::ErrUnimplemented)
	}

	/// Returns true if the entry has exceeded its expiration date
	fn is_expired(&self) -> Result<bool, MensagoError> {

		// Yes, it would make more sense to simply have a stored value which was already parsed,
		// but the necessary code to do the dynamic dispatch to handle this would probably increase
		// complexity by an order of magnitude. We'll sacrifice a tiny bit of performance for 
		// simplicity.
		let expdate = match self.fields.get(&EntryFieldType::Expires) {
			Some(v) => {
				match NaiveDate::parse_from_str(v, "%Y%m%d") {
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
	fn get_text(&self, signature_level: AuthStrType, include_auth: &bool)
		-> Result<(), MensagoError> {

		// TODO: Implement OrgEntry::get_text()

		Err(MensagoError::ErrUnimplemented)
	}
}

static user_field_names: [&str; 12] = [
	"Index",
	"Name",
	"Workspace-ID",
	"User-ID",
	"Domain",
	"Contact-Request-Verification-Key",
	"Contact-Request-Encryption-Key",
	"Encryption-Key",
	"Verification-Key",
	"Time-To-Live",
	"Expires",
	"Timestamp",
];

static user_required_fields: [&str; 10] = [
	"Index",
	"Workspace-ID",
	"Domain",
	"Contact-Request-Verification-Key",
	"Contact-Request-Encryption-Key",
	"Encryption-Key",
	"Verification-Key",
	"Time-To-Live",
	"Expires",
	"Timestamp",
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

	fn _type() -> &'static str {
		return "IndexField"
	}
}

impl fmt::Display for IndexField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl IndexField {
	pub fn from(s: &str) -> Option<IndexField> {

		if !INDEX_PATTERN.is_match(s) {
			return None
		}

		Some(IndexField{ data:String::from(s) })
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

	fn _type() -> &'static str {
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

	fn _type() -> &'static str {
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

	fn _type() -> &'static str {
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

	fn _type() -> &'static str {
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

	fn _type() -> &'static str {
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

	fn _type() -> &'static str {
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
}
