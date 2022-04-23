use hex;
use lazy_static::lazy_static;
use rand::prelude::*;
use regex::Regex;
use std::fmt;

lazy_static! {
	static ref RANDOMID_PATTERN: regex::Regex = 
		Regex::new(r"^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$")
		.unwrap();
	
	static ref USERID_PATTERN: regex::Regex = 
		Regex::new(r"^([a-zA-Z0-9_-]|\.[^.])+$")
		.unwrap();
	
	static ref DOMAIN_PATTERN: regex::Regex = 
		Regex::new(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+$")
		.unwrap();
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum IDType {
	WorkspaceID,
	UserID
}

/// The RandomID class is similar to v4 UUIDs. To obtain the maximum amount of entropy, all bits
/// are random and no version information is stored in them. The only null value for the RandomID
/// is all zeroes. Lastly, the only permissible format for the string version of the RandomID
/// has all letters in lowercase and dashes are placed in the same places as for UUIDs. 
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct RandomID {
	data: String
}

impl RandomID {

	/// Creates a new, empty RandomID. Useful on the rare occasion where you need an empty RandomID
	/// but not generally used. You probably want from_str() or generate().
	pub fn new() -> RandomID {
		return RandomID{ data: String::from("00000000-0000-0000-0000-000000000000")};
	}

	/// Creates a new populated RandomID
	pub fn generate() -> RandomID {
		
		let mut rdata: [u8; 16] = [0; 16];
		rand::thread_rng().fill_bytes(&mut rdata[..]);
		let out = RandomID {
			data: format!("{}-{}-{}-{}-{}", hex::encode(&rdata[0..4]), hex::encode(&rdata[4..6]),
						hex::encode(&rdata[6..8]), hex::encode(&rdata[8..10]),
						hex::encode(&rdata[10..])) };

		out
	}

	/// Creates a RandomID from an existing string and ensures that formatting is correct.
	pub fn from_str(data: &str) -> Option<RandomID> {
		if !RANDOMID_PATTERN.is_match(data) {
			return None
		}

		let mut out = RandomID::new();
		out.data = data.to_lowercase();

		Some(out)
	}

	/// Returns the RandomID as a string
	pub fn as_string(&self) -> &str {
		&self.data
	}

}

impl fmt::Display for RandomID {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	write!(f, "{}", self.data)
	}
}

/// A basic data type for housing Mensago user IDs. User IDs on the Mensago platform must be no
/// more than 64 ASCII characters. These characters may be from the following: lowercase a-z,
/// numbers, a dash, or an underscore. Periods may also be used so long as they are not consecutive.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct UserID {
	data: String,
	idtype: IDType
}

impl UserID {

	/// Creates a UserID from an existing string. If it contains illegal characters, it will
	/// return None. All capital letters will have their case squashed for compliance.
	pub fn from_str(data: &str) -> Option<UserID> {

		if data.len() > 64 || data.len() == 0 {
			return None
		}

		if !USERID_PATTERN.is_match(data) {
			return None
		}

		let mut out = UserID { data: String::from(data), idtype: IDType::UserID };
		out.data = data.to_lowercase();

		out.idtype = if RANDOMID_PATTERN.is_match(&out.data) {
			IDType::WorkspaceID
		} else {
			IDType::UserID
		};

		Some(out)
	}

	/// Creates a UserID from a workspace ID
	pub fn from_wid(wid: &RandomID) -> UserID {
		UserID {
			data: String::from(wid.as_string()),
			idtype: IDType::WorkspaceID,
		}
	}

	/// Returns the UserID as a string
	pub fn as_string(&self) -> &str {
		&self.data
	}

	/// Returns true if the UserID is also a workspace ID.
	pub fn get_type(&self) -> IDType {
		self.idtype
	}
}

impl fmt::Display for UserID {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	write!(f, "{}", self.data)
	}
}


/// A basic data type for housing Internet domains.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct Domain {
	data: String
}

impl Domain {

	/// Creates a Domain from an existing string. If it contains illegal characters, it will
	/// return None. All capital letters will have their case squashed. This type exists to ensure
	/// that valid domains are used across the library
	pub fn from_str(data: &str) -> Option<Domain> {
		if !DOMAIN_PATTERN.is_match(data) {
			return None
		}

		let mut out = Domain { data: String::from(data) };
		out.data = data.to_lowercase();

		Some(out)
	}

	/// Returns the Domain as a string
	pub fn as_string(&self) -> &str {
		&self.data
	}
}

impl fmt::Display for Domain {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	write!(f, "{}", self.data)
	}
}

/// A basic data type representing a full Mensago address. It is used to ensure passing around
/// valid data within the library.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct MAddress {
	pub uid: UserID,
	pub domain: Domain,
}

impl MAddress {

	/// Creates a new MAddress from a string. If the string does not contain a valid Mensago
	/// address, None will be returned.
	pub fn from_str(data: &str) -> Option<MAddress> {

		let parts = data.split("/").collect::<Vec<&str>>();

		if parts.len() != 2 {
			return None
		}
		
		let out = MAddress { uid: UserID::from_str(parts[0])?, domain: Domain::from_str(parts[1])? };

		Some(out)
	}

	/// Creates an MAddress from its components
	pub fn from_parts(uid: &UserID, domain: &Domain) -> MAddress {
		MAddress {
			uid: uid.clone(),
			domain: domain.clone(),
		}
	}

	/// Returns the MAddress as a string
	pub fn as_string(&self) -> String {
		String::from(format!("{}/{}", self.uid, self.domain))
	}

	/// Returns the UserID portion of the address
	pub fn get_uid(&self) -> &UserID {
		&self.uid
	}

	/// Returns the Domain portion of the address
	pub fn get_domain(&self) -> &Domain {
		&self.domain
	}
}

impl fmt::Display for MAddress {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.uid, self.domain)
	}
}

/// A basic data type representing a full Mensago address. It is used to ensure passing around
/// valid data within the library.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct WAddress {
	wid: RandomID,
	domain: Domain,
}

impl WAddress {

	/// Creates a new WAddress from a string. If the string does not contain a valid workspace
	/// address, None will be returned.
	pub fn from_str(data: &str) -> Option<WAddress> {

		let parts = data.split("/").collect::<Vec<&str>>();

		if parts.len() != 2 {
			return None
		}
		
		let out = WAddress { wid: RandomID::from_str(parts[0])?, domain: Domain::from_str(parts[1])? };

		Some(out)
	}

	/// Creates a WAddress from its components
	pub fn from_parts(wid: &RandomID, domain: &Domain) -> WAddress {
		WAddress {
			wid: wid.clone(),
			domain: domain.clone(),
		}
	}

	/// Returns the WAddress as a string
	pub fn as_string(&self) -> String {
		String::from(format!("{}/{}", self.wid, self.domain))
	}

	/// Returns the RandomID portion of the address
	pub fn get_wid(&self) -> &RandomID {
		&self.wid
	}

	/// Returns the Domain portion of the address
	pub fn get_domain(&self) -> &Domain {
		&self.domain
	}
}

impl fmt::Display for WAddress {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.wid, self.domain)
	}
}

/// A basic data type representing an Argon2id password hash. It is used to ensure passing around
/// valid data within the library. This might someday be genericized, but for now it's fine.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct ArgonHash {
	hash: String
}

impl ArgonHash {

	/// Creates a new ArgonHash from the provided password
	pub fn new(password: &str) -> ArgonHash {
		ArgonHash {
			hash: eznacl::hash_password(password, eznacl::HashStrength::Basic)
		}
	}

	/// Returns the object's hash string
	pub fn get_hash(&self) -> &str {
		&self.hash
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn test_randomid() {

		let testid = RandomID::generate();
		
		let strid = RandomID::from_str(testid.as_string());
		assert_ne!(strid, None);
	}
	
	#[test]
	fn test_userid() {

		assert_ne!(UserID::from_str("valid_e-mail.123"), None);
		
		match UserID::from_str("11111111-1111-1111-1111-111111111111") {
			Some(v) => {
				assert!(v.get_type() == IDType::WorkspaceID)
			},
			None => {
				panic!("test_userid failed workspace ID assignment")
			}
		}

		match UserID::from_str("Valid.but.needs_case-squashed") {
			Some(v) => {
				assert_eq!(v.as_string(), "valid.but.needs_case-squashed")
			},
			None => {
				panic!("test_userid failed case-squashing check")
			}
		}
		
		assert_eq!(UserID::from_str("invalid..number1"), None);
		assert_eq!(UserID::from_str("invalid#2"), None);
	}

	#[test]
	fn test_domain() {

		assert_ne!(Domain::from_str("foo-bar.baz.com"), None);

		match Domain::from_str("FOO.bar.com") {
			Some(v) => {
				assert_eq!(v.as_string(), "foo.bar.com")
			},
			None => {
				panic!("test_domain failed case-squashing check")
			}
		}
		
		assert_eq!(Domain::from_str("a bad-id.com"), None);
		assert_eq!(Domain::from_str("also_bad.org"), None);
	}

	#[test]
	fn test_maddress() {
		
		assert_ne!(MAddress::from_str("cats4life/example.com"), None);
		assert_ne!(MAddress::from_str("5a56260b-aa5c-4013-9217-a78f094432c3/example.com"), None);

		assert_eq!(MAddress::from_str("has spaces/example.com"), None);
		assert_eq!(MAddress::from_str(r#"has_a_"/example.com"#), None);
		assert_eq!(MAddress::from_str("\\not_allowed/example.com"), None);
		assert_eq!(MAddress::from_str("/example.com"), None);
		assert_eq!(MAddress::from_str(
			"5a56260b-aa5c-4013-9217-a78f094432c3/example.com/example.com"), None);
		assert_eq!(MAddress::from_str("5a56260b-aa5c-4013-9217-a78f094432c3"), None);
	}

	#[test]
	fn test_waddress() {
		
		assert_ne!(WAddress::from_str("5a56260b-aa5c-4013-9217-a78f094432c3/example.com"), None);
		assert_eq!(WAddress::from_str("cats4life/example.com"), None);
	}
}
