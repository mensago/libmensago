//! This module implements basic filesystem operations inside the database. This is because
//! the files themselves are stored in the database for (a) data protection and (b) easy search.
//! Only attachments are stored outside the database, and this is for bloat protection and ease of 
//! access. The files' names are the same as those on the server to make tracking them easier.
//! Folder names OTOH are stored in the database using the user-facing names (inbox, notes, etc.)
use lazy_static::lazy_static;
use libkeycard::*;
use regex::Regex;
use std::char;
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
/// A folder path could look like '/Inbox/Bills' and a file or message could be something like
/// '/Archive/Bills/a2de7cd4-deee-4a61-aef2-71785ab0d339'.
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

	/// Creates a DBPath from a string. ErrBadValue is returned if the value contains illegal
	/// characters.
	pub fn from(s: &str) -> Result<DBPath, MensagoError> {

		let mut out = DBPath { path: String::new() };
		out.set(s)?;
		Ok(out)
	}

	/// Returns the name of the entry represented by the path
	pub fn basename(&self) -> &str {

		if self.path.len() == 0 {
			return &self.path
		}

		let parts: Vec::<&str> = self.path.split("/").collect();
		parts[parts.len() - 1]
	}

	/// Appends the supplied path to the object
	pub fn push(&mut self, s: &str) -> Result<(), MensagoError> {

		if self.path.len() == 0 {
			return self.set(s)
		}

		let trimmed = s.trim_matches(char::is_whitespace).trim_matches('/');
		if BAD_PATH_CHARS_PATTERN.is_match(trimmed) {
			return Err(MensagoError::ErrBadValue)
		}

		self.path = format!("{}/{}", self.path, trimmed);
		Ok(())
	}

	/// Sets the object to the supplied value
	pub fn set(&mut self, s: &str) -> Result<(), MensagoError> {

		let trimmed = s.trim_matches(char::is_whitespace).trim_matches('/');
		if BAD_PATH_CHARS_PATTERN.is_match(trimmed) {
			return Err(MensagoError::ErrBadValue)
		}

		self.path = format!("/{}/{}", self.path, trimmed);
		Ok(())
	}
}

/// Represents the mapping of a server-side path to one in the database virtual filesystem
#[derive(Debug, Clone)]
pub struct FolderMap {
	fid: RandomID,
	address: WAddress,
	keyid: RandomID,
	path: DBPath,
	permissions: String,
}

// TODO: Implement the DBFS
