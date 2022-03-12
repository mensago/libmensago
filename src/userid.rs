use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;

lazy_static! {
	static ref USERID_PATTERN: regex::Regex = 
		Regex::new(r"^([a-zA-Z0-9_-]|\.[^.])+$")
		.unwrap();
}

/// A basic data type for housing Mensago user IDs. User IDs on the Mensago platform must be no
/// more than 64 ASCII characters. These characters may be from the following: lowercase a-z,
/// numbers, a dash, or an underscore. Periods may also be used so long as they are not consecutive.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct UserID {
	data: String
}

impl UserID {

	/// Creates a UserID from an existing string. If it contains illegal characters, it will
	/// return None. All capital letters will have their case squashed for compliance.
	pub fn from_str(data: &str) -> Option<UserID> {
		if !USERID_PATTERN.is_match(data) {
			return None
		}

		let mut out = UserID { data: String::from(data) };
		out.data = data.to_lowercase();

		Some(out)
	}

	/// Returns the UserID as a string
	pub fn as_string(&self) -> &str {
		&self.data
	}
}

impl fmt::Display for UserID {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	write!(f, "{}", self.data)
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn test_userid() {

		assert_ne!(UserID::from_str("11111111-1111-1111-1111-111111111111"), None);
		assert_ne!(UserID::from_str("valid_e-mail.123"), None);

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
}
