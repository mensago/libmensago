use chrono::prelude::*;
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
	
	// Database exceptions are *bad*. This is returned only when there is a major problem with the
	// data in the database, such as a workspace having no identity entry.
	#[error("Database exception: {0}")]
	ErrDatabaseException(String),

	// Program exceptions are also extremely bad, but also highly unlikely thanks to Rust
	#[error("Program exception: {0}")]
	ErrProgramException(String),

	// Keycard error codes

	#[error("Feature not available")]
	ErrFeatureNotAvailable,
	#[error("Unsupported keycard type")]
	ErrUnsupportedKeycardType,
	#[error("Unsupported signature type")]
	ErrUnsupportedSignatureType,
	#[error("Unsupported field")]
	ErrUnsupportedField,
	#[error("Bad value for field: {0}")]
	ErrBadFieldValue(String),
	#[error("Unsupported hash type")]
	ErrUnsupportedHashType,
	#[error("Unsupported encryption type")]
	ErrUnsupportedEncryptionType,
	#[error("Noncompliant keycard")]
	ErrNoncompliantKeycard,
	#[error("Invalid keycard")]
	ErrInvalidKeycard,
	#[error("Invalid hash")]
	ErrInvalidHash,
	#[error("Hash mismatch")]
	ErrHashMismatch,
	// Returned when attempting to add a signature to a keycard out of the required order, e.g.
	// adding a Custody signature anywhere but first.
	#[error("Out-of-order signature")]
	ErrOutOfOrderSignature,


	// Passthrough errors

	#[error(transparent)]
    IOError(#[from] std::io::Error),

	#[error(transparent)]
    RusqliteError(#[from] rusqlite::Error),

	#[error(transparent)]
	EzNaclError(#[from] eznacl::EzNaclError),
}

/// Returns a string containing the current UTC with second precision in the format
/// YYYYMMDDTHHMMSSZ.
pub fn get_timestamp() -> String {

	let utc: DateTime<Utc> = Utc::now();
	let formatted = utc.format("%Y%m%dT%H%M%SZ");

	String::from(formatted.to_string())
}

/// Returns a string, given a database query
pub fn get_string_from_db(conn: &rusqlite::Connection, query: &str, params: &Vec<String>)
	-> Result<String, MensagoError> {

	let mut stmt = match conn
		.prepare(query) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

	let mut rows = match stmt.query(rusqlite::params_from_iter(params.iter())) {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};

	let option_row = match rows.next() {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};

	// Query unwrapping complete. Start extracting the data
	let row = option_row.unwrap();

	let out = match &row.get::<usize,String>(0) {
		Ok(v) => String::from(v),
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(
				String::from(format!("Error getting string in get_string_from_db(): {}", e))
			))
		}
	};

	Ok(out)
}
