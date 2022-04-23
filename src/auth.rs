use eznacl::*;
use sys_info;
use rusqlite;

use crate::base::*;
use crate::types::*;

pub fn get_credentials(conn: &rusqlite::Connection, waddr: &WAddress)
		-> Result<ArgonHash, MensagoError> {
	
	// For the fully-commented version of this query, see profile::get_identity()
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
	let passhash = ArgonHash::from_str(&row.get::<usize,String>(0).unwrap());
	
	Ok(passhash)
}

/// Sets the password and hash type for the specified workspace
pub fn set_credentials(conn: &rusqlite::Connection, waddr: &WAddress, pwh: &ArgonHash) -> Result<(),MensagoError> {

	check_workspace_exists(&conn, waddr)?;

	match conn.execute("UPDATE workspaces SET password=?1,pwhashtype=?2 WHERE wid=?3 AND domain=?4",
			&[pwh.get_hash(), pwh.get_hashtype(), waddr.get_wid().as_string(),
			waddr.get_domain().as_string()]) {
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}

/// Adds a device ID to a workspace
pub fn add_device_session(conn: &rusqlite::Connection, waddr: &WAddress, devid: &RandomID, 
	devpair: &EncryptionPair, devname: Option<&str>) -> Result<(),MensagoError> {

	if devpair.get_algorithm() != "CURVE25519" {
		return Err(MensagoError::ErrUnsupportedAlgorithm)
	}
	
	check_workspace_exists(&conn, waddr)?;
	
	// Can't have a session on that specified server already
	{
		let mut stmt = match conn.prepare("SELECT address FROM sessions WHERE address=?1") {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};
			
		let mut rows = match stmt.query([waddr.get_wid().as_string()]) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

		match rows.next() {
			Ok(optrow) => {
				match optrow {
					Some(_) => { return Err(MensagoError::ErrExists) },
					None => { /* Do nothing. No existing session. */ }
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};
	}

	let realname = match devname {
		Some(v) => { String::from(v) },
		None => { make_device_name() },
	};

	match conn.execute("INSERT INTO sessions(address, devid, devname, public_key, private_key, os)
		VALUES(?1,?2,?3,?4,?5,?6)",
		[waddr.to_string(), devid.to_string(), realname, devpair.get_public_str(),
		devpair.get_private_str(), os_info::get().os_type().to_string().to_lowercase()]) {
		
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}

/// Removes an authorized device from the workspace
pub fn remove_device_session(conn: &rusqlite::Connection, devid: &RandomID) -> Result<(),MensagoError> {

	// Check to see if the device ID passed to the function exists
	let mut stmt = match conn.prepare("SELECT devid FROM sessions WHERE devid=?1") {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};
		
	let mut rows = match stmt.query([devid.as_string()]) {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};

	match rows.next() {
		Ok(optrow) => {
			match optrow {
				// This means that the device ID wasn't found
				None => { return Err(MensagoError::ErrNotFound) },
				Some(_) => { /* Do nothing. The device exists. */ }
			}
		},
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	};

	match conn.execute("DELETE FROM sessions WHERE devid=?1)", [devid.as_string()]) {
		
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}

/// Returns the device key for a server session
pub fn get_session_keypair(conn: &rusqlite::Connection, waddr: WAddress)
		-> Result<EncryptionPair, MensagoError> {
	
	let out: EncryptionPair;
	{	// Begin Query
		// For the fully-commented version of this code, see profile::get_identity()
	
		let mut stmt = match conn
			.prepare("SELECT public_key,private_key FROM sessions WHERE address=?1") {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		
		let mut rows = match stmt.query([waddr.as_string()]) {
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
		out = match EncryptionPair::from_strings(
			&row.get::<usize,String>(0).unwrap(),
			&row.get::<usize,String>(1).unwrap()) {
			
			Some(v) => v,
			None => { 
				return Err(MensagoError::ErrProgramException(
					String::from("Error obtaining encryption pair from database")
				));
			}
		}

	}	// End Query

	Ok(out)
}

/// Utility function that just checks to see if a specific workspace exists in the database
fn check_workspace_exists(conn: &rusqlite::Connection, waddr: &WAddress)
	-> Result<(),MensagoError> {
	
	// Check to see if the workspace address passed to the function exists
	let mut stmt = match conn.prepare("SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2") {
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
	Ok(())
}

/// Internal function to construct a device name based on platform and OS
fn make_device_name() -> String {
	let hostname = match sys_info::hostname() {
		Ok(v) => v.to_lowercase(),
		Err(_) => {
			// If we can't get the hostname, we've got bigger problems than just a string name, so
			// just use localhost in that instance.
			String::from("localhost")
		}
	};

	let osname = os_info::get()
		.os_type().to_string()
		.to_lowercase();

	format!("{}-{}",hostname, osname)
}

// TODO: Implement add_key

// TODO: Implement remove_key

// TODO: Implement get_key

// TODO: Implement get_key_by_type
