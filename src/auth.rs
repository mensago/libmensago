use eznacl::*;
use libkeycard::*;
use sys_info;
use rusqlite;

use crate::base::*;
use crate::types::*;

/// Gets the password hash for the workspace
pub fn get_credentials(conn: &rusqlite::Connection, waddr: &WAddress)
		-> Result<ArgonHash, MensagoError> {
	
	let mut stmt = conn.prepare("SELECT password FROM workspaces WHERE wid=?1 AND domain=?2")?;
	
	let pwstr = stmt.query_row([waddr.get_wid().as_string(), waddr.get_domain().as_string()],
	|row| {
		Ok(row.get::<usize,String>(0).unwrap())
	})?;

	if pwstr.len() == 0 { return Err(MensagoError::ErrNotFound) }

	Ok(ArgonHash::from_hashstr(&pwstr))
}

/// Sets the password and hash type for the specified workspace
pub fn set_credentials(conn: &rusqlite::Connection, waddr: &WAddress, pwh: Option<&ArgonHash>)
-> Result<(),MensagoError> {

	check_workspace_exists(&conn, waddr)?;
	match pwh {
		Some(v) => {
			match conn.execute(
				"UPDATE workspaces SET password=?1,pwhashtype=?2 WHERE wid=?3 AND domain=?4",
				&[v.get_hash(), v.get_hashtype(), waddr.get_wid().as_string(),
					waddr.get_domain().as_string()]) {
				Ok(_) => Ok(()),
				Err(e) => {
					Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}
		},
		None => {
			match conn.execute(
				"UPDATE workspaces SET password='',pwhashtype='' WHERE wid=?1 AND domain=?2",
				&[waddr.get_wid().as_string(), waddr.get_domain().as_string()]) {
				Ok(_) => Ok(()),
				Err(e) => {
					Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}
		}
	}
}

/// Adds a device ID to a workspace
pub fn add_device_session(conn: &rusqlite::Connection, waddr: &WAddress, devid: &RandomID, 
	devpair: &EncryptionPair, devname: Option<&str>) -> Result<(),MensagoError> {

	check_workspace_exists(&conn, waddr)?;
	
	// Can't have a session on that specified server already
	let mut stmt = conn.prepare("SELECT address FROM sessions WHERE address=?1")?;
	match stmt.exists([waddr.get_wid().as_string()]) {
		Ok(v) => { if v { return Err(MensagoError::ErrExists) }	},
		Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) },
	};

	let realname = match devname {
		Some(v) => { String::from(v) },
		None => { make_device_name() },
	};

	match conn.execute("INSERT INTO sessions(address, devid, devname, public_key, private_key, os)
		VALUES(?1,?2,?3,?4,?5,?6)",
		[waddr.to_string(), devid.to_string(), realname, devpair.get_public_str(),
		devpair.get_private_str(), os_info::get().os_type().to_string().to_lowercase()]) {
		
		Ok(_) => Ok(()),
		Err(e) => {
			Err(MensagoError::ErrDatabaseException(e.to_string()))
		},
	}
}

/// Removes an authorized device from the workspace
pub fn remove_device_session(conn: &rusqlite::Connection, devid: &RandomID)
-> Result<(),MensagoError> {

	let mut stmt = conn.prepare("SELECT devid FROM sessions WHERE devid=?1")?;
	match stmt.exists([devid.as_string()]) {
		Ok(v) => { if v { return Err(MensagoError::ErrExists) }	},
		Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) },
	};
		
	match conn.execute("DELETE FROM sessions WHERE devid=?1", [devid.as_string()]) {
		Ok(_) => Ok(()),
		Err(e) => {
			Err(MensagoError::ErrDatabaseException(e.to_string()))
		},
	}
}

/// Returns the device key for a server session
pub fn get_session_keypair(conn: &rusqlite::Connection, waddr: WAddress)
		-> Result<EncryptionPair, MensagoError> {
	
	let mut stmt = conn.prepare("SELECT public_key,private_key FROM sessions WHERE address=?1")?;
	let (pubstr, privstr) = stmt.query_row([waddr.as_string()], |row| {
		Ok((row.get::<usize,String>(0).unwrap(), row.get::<usize,String>(1).unwrap()))
	})?;

	match EncryptionPair::from_strings(&pubstr, &privstr) {
		Some(v) => Ok(v),
		None => { Err(MensagoError::ErrProgramException(
					String::from("Error obtaining encryption pair from database")))
		}
	}
}

/// Adds a key pair to a workspace.
pub fn add_keypair(conn: &rusqlite::Connection, waddr: &WAddress, pubkey: &CryptoString,
	privkey: &CryptoString, keytype: &KeyType, category: &KeyCategory) -> Result<(), MensagoError> {
	
	let pubhash = match eznacl::get_hash("sha-256", pubkey.as_bytes()) {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrProgramException(String::from(e.to_string())));
		}
	};

	let mut stmt = conn.prepare("SELECT keyid FROM keys WHERE keyid=?1")?;
	match stmt.exists([pubhash.as_str()]) {
		Ok(v) => { if v { return Err(MensagoError::ErrExists) }	},
		Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) },
	};

	let timestamp = get_timestamp();

	let type_string = match keytype {
		KeyType::AsymEncryptionKey => "asymmetric",
		KeyType::SigningKey => "signing",

		// add_key() is used for symmetric keys
		KeyType::SymEncryptionKey => {
			return Err(MensagoError::ErrTypeMismatch)
		},
	};

	let category_string = match category {
		KeyCategory::ConReqEncryption => "crencryption",
		KeyCategory::ConReqSigning => "crsigning",
		KeyCategory::Encryption => "encryption",
		KeyCategory::Signing => "signing",
		KeyCategory::Folder => "folder",
		KeyCategory::PrimarySigning => "orgsigning",
		KeyCategory::SecondarySigning => "altorgsigning",
		KeyCategory::Storage => "storage",
	};

	match conn.execute("INSERT INTO keys(keyid,address,type,category,private,public,timestamp)
		VALUES(?1,?2,?3,?4,?5,?6,?7)",
		[pubhash.as_str(), &waddr.to_string(), type_string, category_string, privkey.as_str(), 
		pubkey.as_str(), &timestamp]) {
		
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}

/// Adds a single symmetric key to a workspace.
pub fn add_key(conn: &rusqlite::Connection, waddr: &WAddress, key: &CryptoString, 
	category: &KeyCategory) -> Result<(), MensagoError> {
	
	let keyhash = match eznacl::get_hash("sha-256", key.as_bytes()) {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrProgramException(String::from(e.to_string())));
		}
	};

	let mut stmt = conn.prepare("SELECT keyid FROM keys WHERE keyid=?1")?;
	match stmt.exists([keyhash.as_str()]) {
		Ok(v) => { if v { return Err(MensagoError::ErrExists) }	},
		Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) },
	};
	
	let timestamp = get_timestamp();

	match conn.execute("INSERT INTO keys(keyid,address,type,category,private,public,timestamp)
		VALUES(?1,?2,?3,?4,?5,?6,?7)",
		[keyhash.as_str(), &waddr.to_string(), "symmetric", &category.to_string(), key.as_str(), 
		key.as_str(), &timestamp]) {
		
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}

/// Deletes a cryptography key from a workspace. Note that the algorithm must match, i.e. if a key
/// is stored using a BLAKE2B-256 hash, passing a BLAKE3-256 hash of the exact same key will result
/// in a ErrNotFound error.
pub fn remove_key(conn: &rusqlite::Connection, keyhash: &CryptoString) -> Result<(), MensagoError> {

	let mut stmt = conn.prepare("SELECT keyid FROM keys WHERE keyid=?1")?;
	match stmt.exists([keyhash.as_str()]) {
		Ok(v) => { if !v { return Err(MensagoError::ErrNotFound) }	},
		Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) },
	};

	match conn.execute("DELETE FROM keys WHERE keyid=?1)", [keyhash.as_str()]) {
		
		Ok(_) => { return Ok(()) },
		Err(e) => {
			return Err(MensagoError::ErrDatabaseException(e.to_string()))
		}
	}
}

/// Returns a pair of CryptoStrings, where the public key is in element 0 and the private key is in
/// element 1. This is to accommodate retrieval of all key types. If a symmetric key is obtained
/// through this call, the public and private key values will be the same.
pub fn get_keypair(conn: &rusqlite::Connection, keyhash: &CryptoString)
	-> Result<[CryptoString; 2], MensagoError> {

	let mut stmt = conn.prepare("SELECT public,private FROM keys WHERE keyid=?1")?;
	let (pubstr, privstr) = stmt.query_row([keyhash.as_str()], |row| {
		Ok((row.get::<usize,String>(0).unwrap(), row.get::<usize,String>(1).unwrap()))
	})?;

	if pubstr.len() == 0 || privstr.len() == 0 {
		return Err(MensagoError::ErrEmptyData)
	}

	let pubcs = CryptoString::from(&pubstr);
	let privcs = CryptoString::from(&privstr);

	if pubcs.is_none() || privcs.is_none() {
		return Err(MensagoError::ErrDatabaseException(
			String::from("Bad key value in database in get_keypair()")
		))
	}

	Ok([pubcs.unwrap(), privcs.unwrap()])
}

/// Returns a keypair based on its category
pub fn get_key_by_category(conn: &rusqlite::Connection, category: &KeyCategory)
	-> Result<[CryptoString; 2], MensagoError> {

	let mut stmt = conn.prepare("SELECT public,private FROM keys WHERE category=?1")?;
	let (pubstr, privstr) = stmt.query_row([category.to_string()], |row| {
		Ok((row.get::<usize,String>(0).unwrap(), row.get::<usize,String>(1).unwrap()))
	})?;

	if pubstr.len() == 0 || privstr.len() == 0 {
		return Err(MensagoError::ErrEmptyData)
	}

	let pubcs = CryptoString::from(&pubstr);
	let privcs = CryptoString::from(&privstr);

	if pubcs.is_none() || privcs.is_none() {
		return Err(MensagoError::ErrDatabaseException(
			String::from("Bad key value in database in get_keypair()")
		))
	}

	Ok([pubcs.unwrap(), privcs.unwrap()])
}

/// Utility function that just checks to see if a specific workspace exists in the database
fn check_workspace_exists(conn: &rusqlite::Connection, waddr: &WAddress)
	-> Result<(),MensagoError> {

	let mut stmt = conn.prepare("SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2")?;
	match stmt.exists([waddr.get_wid().as_string(), waddr.get_domain().as_string()]) {
		Ok(v) => { if !v { return Err(MensagoError::ErrNotFound) }	},
		Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) },
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

#[cfg(test)]
mod tests {
	use crate::*;
	use libkeycard::*;
	use std::env;
	use std::fs;
	use std::path::PathBuf;
	use std::str::FromStr;

	// Sets up the path to contain the profile tests
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

	fn setup_profile(testname: &str, path: &PathBuf) -> Result<ProfileManager, MensagoError> {

		 let mut profman = ProfileManager::new(&path);
		 let _ = match profman.create_profile("Primary") {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error creating profile 'Primary': {}", testname, e.to_string())))
			}
		 };

		match profman.activate_profile("Primary") {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error activating profile 'Primary': {}", testname, e.to_string())))
			}
		}

		Ok(profman)
	}

	fn setup_workspace(testname: &str, profpath: &PathBuf) -> Result<Workspace, MensagoError> {

		// Hash of "CheeseCustomerSmugnessDelegatorGenericUnaudited"
		let pw = String::from("$argon2id$v=19$m=1048576,t=1,p=2$jc/H+Cn1NwJBJOTmFqAdlA$\
			b2zoU9ZNhHlo/ZYuSJwoqUAXEdf1cbN3fxmbQhP0zJc");

		let mut w = Workspace::new(profpath);
		match w.generate(&UserID::from("csimons").unwrap(),
			Domain::from("example.com").as_ref().unwrap(),
			RandomID::from("b5a9367e-680d-46c0-bb2c-73932a6d4007").as_ref().unwrap(), &pw) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error generating workspace: {}", testname, e.to_string())))
			}
		}

		let pwhash = ArgonHash::from_hashstr(&pw);
		match w.add_to_db(&pwhash) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error adding workspace to db: {}", testname, e.to_string())))
			}
		}

		Ok(w)
	}


	#[test]
	fn get_set_credentials() -> Result<(), MensagoError> {

		let testname = String::from("get_set_credentials");
		let test_path = setup_test(&testname);

		let _ = setup_profile(&testname, &test_path)?;

		let mut profile_path = test_path.clone();
		profile_path.push("primary");
		let w = setup_workspace(&testname, &profile_path)?;

		let conn = match w.open_storage() {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error connecting to workspace db: {}", testname, e.to_string())))
			}
		};

		// Case #1: get credentials
		match get_credentials(&conn, &w.get_waddress().unwrap()) {
			Ok(v) => {
				let pwhash = ArgonHash::from_hashstr("$argon2id$v=19$m=1048576,t=1,p=2\
				$jc/H+Cn1NwJBJOTmFqAdlA$b2zoU9ZNhHlo/ZYuSJwoqUAXEdf1cbN3fxmbQhP0zJc");

				if v != pwhash {
					println!("Wanted:\n{}-----\nGot:\n{}", pwhash, v);
					return Err(MensagoError::ErrProgramException(
						format!("{}: credential mismatch", testname)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting credentials: {}", testname, e.to_string())))
			}
		};

		// Case #2: set credentials
		
		// Hash of "GloriousBroadlyBackerOverloadBoxcarBrittle"
		let newpw = String::from("$argon2id$v=19$m=1048576,t=1,p=2\
		$46qy9bqnd0CBmq82X01Xjw$+VUx+mkUvFxDE0aum/h6sGA92JeB7CxZolNAoK8iUOY");
		let newhash = ArgonHash::from_hashstr(&newpw);

		match set_credentials(&conn, &w.get_waddress().unwrap(), Some(&newhash)) {
			Ok(_) => {
				match get_credentials(&conn, &w.get_waddress().unwrap()) {
					Ok(v) => {
						if v != newhash {
							println!("Wanted:\n{}-----\nGot:\n{}", newhash, v);
							return Err(MensagoError::ErrProgramException(
								format!("{}: set_credentials value mismatch", testname)))
						}
					},
					Err(e) => {
						return Err(MensagoError::ErrProgramException(
							format!("{}: error getting credentials: {}", testname, e.to_string())))
					},
				};
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error setting credentials: {}", testname, e.to_string())))
			}
		}

		// Case #3: clearing credentials
		match set_credentials(&conn, &w.get_waddress().unwrap(), None) {
			Ok(_) => {
				match get_credentials(&conn, &w.get_waddress().unwrap()) {
					Ok(_) => {
						return Err(MensagoError::ErrProgramException(
							format!("{}: failed to clear credentials", testname)))
					},
					Err(_) => (),
				};
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error setting credentials: {}", testname, e.to_string())))
			}
		}

		Ok(())
	}
}

// TODO: Finish tests for auth module
