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

#[cfg(test)]
mod tests {
	use crate::*;
	use std::env;
	use std::fs;
	use std::path::PathBuf;
	use std::str::FromStr;

	fn setup_test(name: &str) -> PathBuf {
		if name.len() < 1 {
			panic!("Invalid name {} in setup_test", name);
		}
		let args: Vec<String> = env::args().collect();
		let test_path = PathBuf::from_str(&args[0]).unwrap();
		let mut test_path = test_path.parent().unwrap().to_path_buf();
		test_path.push("testfiles");
		test_path.push(name);

		if test_path.exists() {
			fs::remove_dir_all(&test_path).unwrap();
		}
		fs::create_dir_all(&test_path).unwrap();

		test_path
	}

	#[test]
	fn test_get_string_from_db() -> Result<(), MensagoError> {

		let testname = String::from("get_string_from_db");
		let mut dbpath = setup_test(&testname);
		dbpath.push("test.db");

		let conn = match rusqlite::Connection::open(&dbpath) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};
		
		
		match conn.execute("CREATE table 'folders'(
				'fid' TEXT NOT NULL UNIQUE,
				'address' TEXT NOT NULL,
				'keyid' TEXT NOT NULL,
				'path' TEXT NOT NULL,
				'name' TEXT NOT NULL,
				'permissions' TEXT NOT NULL);", []) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
			}
		}

		match conn.execute("INSERT INTO folders(fid,address,keyid,path,name,permissions)
		VALUES('11111111-2222-3333-4444-555555666666',
			'aaaaaaaa-bbbb-cccc-dddd-eeeeeeffffff/example.com',
			'SHA-256:R(qY?qdXsJZx#GASmI@xeV28`Os7LWAl4el)t~uG',
			'/files/attachments',
			'attachments',
			'admin'
		)", []) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		}

		let v = Vec::<String>::new();
		match get_string_from_db(&conn,
		"SELECT address FROM folders where fid='11111111-2222-3333-4444-555555666666'", &v) {
			Ok(v) => {
				if v != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeffffff/example.com" {
					return Err(MensagoError::ErrProgramException(format!(
						"test_get_string_from_db: value mismatch: got {}", v)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error get folder mapping field: {}", testname, e.to_string())))
			}
		}

		let foldermap = String::from("11111111-2222-3333-4444-555555666666");
		let fields = [
			(String::from("address"), foldermap.clone()),
			(String::from("keyid"), String::from("SHA-256:R(qY?qdXsJZx#GASmI@xeV28`Os7LWAl4el)t~uG")),
			(String::from("path"), String::from("/files/attachments")),
			(String::from("name"), String::from("attachments")),
			(String::from("permissions"), String::from("admin")),
		];
		// Check all fields
		for pair in fields {
			match get_string_from_db(&conn, "SELECT address FROM folders WHERE fid='11111111-2222-3333-4444-555555666666'",
				// &vec![pair.0.clone(), foldermap.clone()]) {
				// &vec![pair.0.clone()]) {
				&vec![]) {
					Ok(v) => {
					if v != pair.1 {
						return Err(MensagoError::ErrProgramException(format!(
							"test_dbpath: wanted {} for {}, got {}", &pair.1, &pair.0, v)))
					}
				},
				Err(e) => {
					return Err(MensagoError::ErrProgramException(
						format!("{}: error get folder mapping field {}: {}",
							 testname, &pair.0, e.to_string())))
				}
			}
		}

		Ok(())
	}
}
