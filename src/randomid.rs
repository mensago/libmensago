use std::fmt;
use hex;
use lazy_static::lazy_static;
use rand::prelude::*;
use regex::Regex;

lazy_static! {
	static ref RANDOMID_PATTERN: regex::Regex = 
		Regex::new(r"[\da-fA-F]{8}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{4}-[\da-fA-F]{12}")
		.unwrap();
}

/// The RandomID class is similar to v4 UUIDs. To obtain the maximum amount of entropy, all bits
/// are random and no version information is stored in them. The only null value for the RandomID
/// is all zeroes. Lastly, the only permissible format for the string version of the RandomID
/// has all letters in lowercase and dashes are placed in the same places as for UUIDs. 
#[derive(Debug, PartialEq, PartialOrd)]
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

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn test_randomid() {

		let testid = RandomID::generate();
		
		let strid = RandomID::from_str(testid.as_string());
		assert_ne!(strid, None);
	}
}
