use hex;
use rand::prelude::*;

/// The RandomID class is similar to v4 UUIDs. To obtain the maximum amount of entropy, all bits
/// are random and no version information is stored in them. The only null value for the RandomID
/// is all zeroes. Lastly, the only permissible format for the string version of the RandomID
/// has all letters in lowercase and dashes are placed in the same places as for UUIDs. 
#[derive(Debug)]
pub struct RandomID {
	data: String
}

impl RandomID {

	/// Creates a new, empty RandomID. Useful on the rare occasion where you need an empty RandomID
	/// but not generally used. You probably want from_str() or generate().
	pub fn new() -> RandomID {
		return RandomID{ data: String::from("00000000-0000-0000-0000-000000000000")};
	}

	pub fn generate() -> RandomID {
		
		let mut rdata: [u8; 16] = [0; 16];
		rand::thread_rng().fill_bytes(&mut rdata[..]);
		let out = RandomID {
			data: format!("{}-{}-{}-{}-{}", hex::encode(&rdata[0..8]), hex::encode(&rdata[8..12]),
						hex::encode(&rdata[12..16]), hex::encode(&rdata[16..20]),
						hex::encode(&rdata[20..])) };

		out
	}

	pub fn as_string(&self) -> &str {
		&self.data
	}
}