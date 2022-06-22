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

	let row = match option_row {
		Some(v) => v,
		None => { return Err(MensagoError::ErrNotFound) },
	};

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
