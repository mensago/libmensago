use std::fmt;
use std::string;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Type to hold status information from a Mensago protocol command response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Error)]
pub struct CmdStatus {
	pub code: u16,
	pub description: String,
	pub info: String,
}

impl fmt::Display for CmdStatus {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if self.info.len() > 0 {
			write!(f, "{}: {} ({})", self.code, self.description, self.info)
		} else {
			write!(f, "{}: {}", self.code, self.description)
		}
	}
}

#[derive(Error, Debug)]
pub enum MensagoError {

	// General error codes
	#[error("Empty data error")]
	ErrEmptyData,
	#[error("Bad value")]
	ErrBadValue,
	#[error("Resource already exists")]
	ErrExists,
	#[error("Filesystem error")]
	ErrFilesytemError,
	#[error("Not found")]
	ErrNotFound,
	#[error("Reserved")]
	ErrReserved,
	#[error("Type mismatch")]
	ErrTypeMismatch,
	#[error("Unsupported algorithm")]
	ErrUnsupportedAlgorithm,
	#[error("Function unimplemented")]
	ErrUnimplemented,
	#[error("Invalid frame")]
	ErrInvalidFrame,
	#[error("Invalid size")]
	ErrSize,
	#[error("Bad session")]
	ErrBadSession,
	#[error("Bad message")]
	ErrBadMessage,
	
	// Database exceptions are *bad*. This is returned only when there is a major problem with the
	// data in the database, such as a workspace having no identity entry.
	#[error("Database exception: {0}")]
	ErrDatabaseException(String),

	// Program exceptions are also extremely bad, but also highly unlikely thanks to Rust
	#[error("Program exception: {0}")]
	ErrProgramException(String),

	// Protocol errors
	#[error(transparent)]
	ErrProtocol(#[from] CmdStatus),
	#[error("schema failure")]
	ErrSchemaFailure,


	// Passthrough errors

	#[error(transparent)]
	EzNaclError(#[from] eznacl::EzNaclError),

	#[error(transparent)]
    IOError(#[from] std::io::Error),

	#[error(transparent)]
    LKCError(#[from] libkeycard::LKCError),

	#[error(transparent)]
    RusqliteError(#[from] rusqlite::Error),

	#[error(transparent)]
	SerdeError(#[from] serde_json::Error),

	#[error(transparent)]
	Utf8Error(#[from] string::FromUtf8Error),
}
