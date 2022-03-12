use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;

lazy_static! {
	static ref USERID_PATTERN: regex::Regex = 
		Regex::new(r"^([a-zA-Z0-9_-]|\.[^.])+$")
		.unwrap();
	
	static ref WID_PATTERN: regex::Regex = 
		Regex::new(r"^[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}$")
		.unwrap();
	
	static ref DOMAIN_PATTERN: regex::Regex = 
		Regex::new(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+$")
		.unwrap();
}

/// A basic data type for housing Mensago user IDs. User IDs on the Mensago platform must be no
/// more than 64 ASCII characters. These characters may be from the following: lowercase a-z,
/// numbers, a dash, or an underscore. Periods may also be used so long as they are not consecutive.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct UserID {
	data: String,
	wid: bool
}

impl UserID {

	/// Creates a UserID from an existing string. If it contains illegal characters, it will
	/// return None. All capital letters will have their case squashed for compliance.
	pub fn from_str(data: &str) -> Option<UserID> {
		if !USERID_PATTERN.is_match(data) {
			return None
		}

		let mut out = UserID { data: String::from(data), wid: false };
		out.data = data.to_lowercase();

		if WID_PATTERN.is_match(&out.data) {
			out.wid = true;
		}

		Some(out)
	}

	/// Returns the UserID as a string
	pub fn as_string(&self) -> &str {
		&self.data
	}

	/// Returns true if the UserID is also a workspace ID.
	pub fn is_wid(&self) -> bool {
		self.wid
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

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn test_userid() {

		assert_ne!(UserID::from_str("valid_e-mail.123"), None);
		
		match UserID::from_str("11111111-1111-1111-1111-111111111111") {
			Some(v) => {
				assert!(v.is_wid())
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
}
