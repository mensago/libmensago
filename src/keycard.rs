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
	Type,
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
			"Type" => Some(EntryFieldType::Type),
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
			EntryFieldType::Type => TypeField::new(s),
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
			EntryFieldType::Type => write!(f, "Type"),
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

impl fmt::Display for AuthStrType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			AuthStrType::Custody => write!(f, "Custody-Signature"),
			AuthStrType::PrevHash => write!(f, "Previous-Hash"),
			AuthStrType::Hash => write!(f, "Hash"),
			AuthStrType::Organization => write!(f, "Organization-Signature"),
			AuthStrType::User => write!(f, "User-Signature"),
		}
	}
}

impl AuthStrType {
	pub fn from(s: &str) -> Option<AuthStrType> {
		match s {
			"Custody-Signature" => Some(AuthStrType::Custody),
			"Previous-Hash" => Some(AuthStrType::PrevHash),
			"Hash" => Some(AuthStrType::Hash),
			"Organization-Signature" => Some(AuthStrType::Organization),
			"User-Signature" => Some(AuthStrType::User),
			&_ => None,
		}
	}
}

// SignatureBlock abstracts away the logic for handling signatures for keycard entries
pub trait SignatureBlock {

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


// TODO: Implement UserSigBlock

/// A verified type for handling keycard type fields
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct TypeField {
	data: String
}

impl VerifiedString for TypeField {

	fn get(&self) -> &str {
		&self.data
	}

	fn _type(&self) -> &'static str {
		return "TypeField"
	}
}

impl fmt::Display for TypeField {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.data)
	}
}

impl TypeField {

	pub fn from(s: &str) -> Option<TypeField> {

		let trimmed = s.trim();

		match trimmed {
			"User" => Some(TypeField{ data:String::from(trimmed) }),
			"Organization" => Some(TypeField{ data:String::from(trimmed) }),
			_ => None,
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
			Err(_) => None,
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
			Ok(_) => {
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

		match chrono::NaiveDateTime::parse_from_str(trimmed, "%Y%m%dT%H%MZ") {
			Ok(_) => {
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
		
		if LANGUAGE_PATTERN.is_match(s) {
			Some(LanguageField{ data: String::from(trimmed) })	
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
