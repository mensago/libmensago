use lazy_static::lazy_static;
use libkeycard::*;
use regex::Regex;
use std::fmt;
use crate::base::*;

lazy_static! {
	#[doc(hidden)]
	static ref BAD_PATH_CHARS_PATTERN: regex::Regex = 
		Regex::new(r#"[\p{C}\\]"#)
		.unwrap();
}

/// Represents a path in the database virtual filesystem. Slashes are the path separator character.
/// The only printable characters not permitted in these paths are backslashes and control
/// characters. Trailing slashes and leading and trailing whitespace are stripped to avoid problems.
#[derive(Debug, Clone)]
pub struct DBPath {
	path: String,
}

impl fmt::Display for DBPath {

	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.path)
	}
}

impl DBPath {

	/// Creates an empty DBPath instance
	pub fn new() -> DBPath {
		DBPath { path: String::new() }
	}

	pub fn from(s: &str) -> Result<DBPath, MensagoError> {

		let trimmed = s.trim().trim_end_matches("/");
		if BAD_PATH_CHARS_PATTERN.is_match(trimmed) {
			return Err(MensagoError::ErrBadValue)
		}

		Ok(DBPath { path: String::from(trimmed) })
	}
}

/// Represents the mapping of a server-side path to one in the database virtual filesystem
pub struct FolderMap {
	fid: RandomID,
	address: WAddress,
	keyid: RandomID,
	path: DBPath,
	permissions: String,
}

// TODO: Implement the DBFS
