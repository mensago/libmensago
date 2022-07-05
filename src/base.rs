use thiserror::Error;

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
	
	// Database exceptions are *bad*. This is returned only when there is a major problem with the
	// data in the database, such as a workspace having no identity entry.
	#[error("Database exception: {0}")]
	ErrDatabaseException(String),

	// Program exceptions are also extremely bad, but also highly unlikely thanks to Rust
	#[error("Program exception: {0}")]
	ErrProgramException(String),

	// Passthrough errors

	#[error(transparent)]
	EzNaclError(#[from] eznacl::EzNaclError),

	#[error(transparent)]
    IOError(#[from] std::io::Error),

	#[error(transparent)]
    LKCError(#[from] libkeycard::LKCError),

	#[error(transparent)]
    RusqliteError(#[from] rusqlite::Error),
}
