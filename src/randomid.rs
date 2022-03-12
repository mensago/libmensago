use rand::prelude::*;

/// The RandomID class is similar to v4 UUIDs. To obtain the maximum amount of entropy, all bits
/// are random and no version information is stored in them. The only null value for the RandomID
/// is all zeroes. Lastly, the only permissible format for the string version of the RandomID
/// has all letters in lowercase and dashes are placed in the same places as for UUIDs. 
pub struct RandomID {
	data: [u8; 16]
}

impl RandomID {

	/// Creates a new, empty RandomID. Useful on the rare occasion where you need an empty RandomID
	/// but not generally used. You probably want from_str() or generate().
	pub fn new() -> RandomID {
		return RandomID{ data: [0u8; 16]};
	}

	pub fn generate() -> RandomID {
		
		let mut out = RandomID::new();
		rand::thread_rng().fill_bytes(&mut out.data[..]);

		out
	}
}