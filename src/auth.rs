use std::path::{PathBuf};
use rusqlite;
use crate::base::*;
use crate::types::*;

pub fn get_credentials(path: PathBuf, waddr: WAddress) -> Result<ArgonHash, MensagoError> {
	
	let mut dbpath = path.clone();
	dbpath.push("storage.db");

	let passhash: ArgonHash;

	{	// Begin Query
		// For the fully-commented version of this code, see profile::get_identity()
		let conn = match rusqlite::Connection::open_with_flags(dbpath, 
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
	
		let mut stmt = match conn
			.prepare("SELECT password,pwhashtype FROM workspaces WHERE wid=?1 AND domain=?2") {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		
		let mut rows = match stmt.query([waddr.get_wid().as_string(),
			waddr.get_domain().as_string()]) {
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
		passhash = ArgonHash::from_str(&row.get::<usize,String>(0).unwrap());

	}	// End Query
	
	Ok(passhash)
}

/// Sets the password and hash type for the specified workspace
pub fn set_credentials(dbpath: PathBuf, waddr: WAddress, pwh: ArgonHash) -> Result<(),MensagoError> {

	let conn = match rusqlite::Connection::open_with_flags(dbpath, 
		rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};
	
	
	// Check to see if the workspace address passed tothe function exists
	let mut stmt = match conn.prepare("SELECT wid FROM workspaces WHERE wid=?! AND domain=?2") {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};
		
	let mut rows = match stmt.query([waddr.get_wid().as_string(), waddr.get_domain().as_string()]) {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};

	match rows.next() {
		Ok(optrow) => {
			match optrow {
				// This means that the workspace ID wasn't found
				None => { return Err(MensagoError::ErrNotFound) },
				Some(_) => { /* Do nothing. The workspace exists. */ }
			}
		},
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};

	match conn.execute("UPDATE workspaces SET password=?1,pwhashtype=?2 WHERE wid=?3 AND domain=?4",
			&[pwh.get_hash(), pwh.get_hashtype(), waddr.get_wid().as_string(),
			waddr.get_domain().as_string()]) {
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}
