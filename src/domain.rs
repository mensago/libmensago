use lazy_static::lazy_static;
use regex::Regex;
use std::fmt;

lazy_static! {
	static ref DOMAIN_PATTERN: regex::Regex = 
		Regex::new(r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+$")
		.unwrap();
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
