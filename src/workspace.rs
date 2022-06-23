use eznacl::*;
use libkeycard::*;
use std::fs;
use std::path::PathBuf;
use crate::auth;
use crate::base::*;
use crate::dbfs::*;
use crate::types::*;

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct Workspace {
	dbpath: PathBuf,
	secretspath: PathBuf,
	path: PathBuf,
	uid: Option<UserID>,
	wid: Option<RandomID>,
	domain: Option<Domain>,
	_type: String,
	pw: String,
}

impl Workspace {

	/// Creates a new, uninitialized Workspace object
	pub fn new(path: &PathBuf) -> Workspace {

		let mut storage = path.clone();
		storage.push("storage.db");

		let mut secrets = path.clone();
		secrets.push("secrets.db");
		
		return Workspace{
			dbpath: storage,
			secretspath: secrets,
			path: path.clone(),
			uid: None,
			wid: None,
			domain: None,
			_type: String::from("identity"),
			pw: String::from(""),
		}
	}

	/// Returns the workspace ID of the workspace, assuming one has been set
	pub fn get_wid(&self) -> Option<RandomID> {
		self.wid.clone()
	}

	/// Returns the user ID of the workspace, assuming one has been set
	pub fn get_uid(&self) -> Option<UserID> {
		self.uid.clone()
	}

	/// Returns the domain of the workspace, assuming one has been set
	pub fn get_domain(&self) -> Option<Domain> {
		self.domain.clone()
	}

	/// Creates all the data needed for an individual workspace account
	pub fn generate(&mut self, uid: &UserID, server: &Domain, wid: &RandomID, pw: &str) 
		-> Result<(),MensagoError> {
		
		self.uid = Some(uid.clone());
		self.wid = Some(wid.clone());
		self.domain = Some(server.clone());
		self.pw = String::from(pw);

		// This variable will be needed by the unimplemented section of generate()
		//let address = MAddress::from_parts(&UserID::from_wid(wid), server);
		let waddr = WAddress::from_parts(&wid, &server);
		
		let conn = match rusqlite::Connection::open_with_flags(&self.secretspath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};
		
		// Generate and add the workspace's various crypto keys

		let crepair = eznacl::EncryptionPair::generate().unwrap();
		auth::add_keypair(&conn, &waddr, &crepair.get_public_key(), &crepair.get_private_key(),
			&KeyType::AsymEncryptionKey, &KeyCategory::ConReqEncryption)?;

		let crspair = eznacl::SigningPair::generate().unwrap();
		auth::add_keypair(&conn, &waddr, &crspair.get_public_key(), &crspair.get_private_key(),
			&KeyType::SigningKey, &KeyCategory::ConReqSigning)?;

		let epair = eznacl::EncryptionPair::generate().unwrap();
		auth::add_keypair(&conn, &waddr, &epair.get_public_key(), &epair.get_private_key(),
			&KeyType::AsymEncryptionKey, &KeyCategory::Encryption)?;

		let spair = eznacl::SigningPair::generate().unwrap();
		auth::add_keypair(&conn, &waddr, &spair.get_public_key(), &spair.get_private_key(),
			&KeyType::SigningKey, &KeyCategory::Signing)?;

		let folderkey = eznacl::SecretKey::generate().unwrap();
		auth::add_key(&conn, &waddr, &folderkey.get_public_key(), &KeyCategory::Folder)?;

		let storagekey = eznacl::SecretKey::generate().unwrap();
		auth::add_key(&conn, &waddr, &storagekey.get_public_key(), &KeyCategory::Storage)?;
		
		let fkeyhash = get_hash("SHA-256", folderkey.get_public_str().as_bytes())?;
		
		for folder in [
			"/messages",
			"/contacts",
			"/events",
			"/tasks",
			"/notes",
			"/files",
			"/files/attachments"] {
			
			self.add_folder(&FolderMap{
				fid: RandomID::generate(),
				address: waddr.clone(),
				keyid: fkeyhash.clone(),
				path: DBPath::from(folder).unwrap(),
				permissions: String::from("admin"),
			})?;
		}

		// Create the folders for files and attachments
		let mut attachmentdir = self.path.clone();
		attachmentdir.push("files");
		attachmentdir.push("attachments");
		if !attachmentdir.exists() {
			fs::create_dir_all(attachmentdir)?;
		}

		self.set_userid(uid)?;
		
		Ok(())
	}

	/// Loads the workspace information from the local database. If no workspace ID is specified,
	/// the identity workspace for the profile is loaded.
	pub fn load_from_db(&mut self, wid: Option<RandomID>) -> Result<(), MensagoError> {

		// For the fully-commented version of this code, see profile::get_identity()

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};
		
		let widstr = match wid {
			Some(w) => { String::from(w.to_string()) },
			None => { 
				let params = Vec::<String>::new();
				match get_string_from_db(&conn,
					"SELECT wid FROM workspaces WHERE type = 'identity'", &params) {
					Ok(v) => v,
					Err(e) => {
						return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
					}
				}
			},
		};

		let mut stmt = match conn
			.prepare("SELECT domain,userid FROM workspaces WHERE wid = ?1") {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		
		let mut rows = match stmt.query([widstr.to_string()]) {
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

		self.wid = match RandomID::from(&widstr.to_string()) {
			Some(v) => Some(v),
			None => {
				return Err(MensagoError::ErrProgramException(String::from(
					"BUG: Invalid workspace ID in load_from_db")))
			},
		};

		self.domain = match &row.get::<usize,String>(0) {
			Ok(v) => {
				match Domain::from(v) {
					Some(d) => Some(d),
					None => {
						return Err(MensagoError::ErrDatabaseException(
							String::from(format!("Bad domain {} in load_from_db()", v))
						))
					}
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(
					String::from(format!("Error getting domain in load_from_db(): {}", e))
				))
			}
		};

		self.uid = match &row.get::<usize,String>(0) {
			Ok(v) => {
				match UserID::from(v) {
					Some(d) => Some(d),
					None => {
						return Err(MensagoError::ErrDatabaseException(
							String::from(format!("Bad user ID {} in load_from_db()", v))
						))
					}
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(
					String::from(format!("Error getting user ID in load_from_db(): {}", e))
				))
			}
		};

		Ok(())
	}

	/// Adds the workspace instance to the storage database as the profile's identity workspace
	pub fn add_to_db(&self, pw: &ArgonHash) -> Result<(), MensagoError> {

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};

		let params = Vec::<String>::new();
		match get_string_from_db(&conn,
			"SELECT wid FROM workspaces WHERE type = 'identity'", &params) {
			Ok(_) => { return Err(MensagoError::ErrExists) },
			Err(_) => (),
		}

		let uidstr = match &self.uid {
			Some(v) => String::from(v.to_string()),
			None => String::new(),
		};
	
		if uidstr.len() > 0 {
			match conn.execute("INSERT INTO workspaces(wid,userid,domain,password,pwhashtype,type)
			VALUES(?1,?2,?3,?4,?5,?6)",
				&[self.wid.as_ref().unwrap().as_string(), &uidstr, 
					self.domain.as_ref().unwrap().as_string(), pw.get_hash(), pw.get_hashtype(), 
					&self._type]) {
				Ok(_) => { return Ok(()) },
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}
		} else {
			match conn.execute("INSERT INTO workspaces(wid,userid,domain,password,pwhashtype,type)
			VALUES(?1,?2,?3,?4,?5)",
				&[self.wid.as_ref().unwrap().as_string(), self.domain.as_ref().unwrap().as_string(),
					pw.get_hash(), pw.get_hashtype(), &self._type]) {
				Ok(_) => { return Ok(()) },
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}
		}
	}

	/// Removes ALL DATA associated with a workspace. Don't call this unless you mean to erase all
	/// evidence that a particular workspace ever existed.
	pub fn remove_from_db(&self) -> Result<(), MensagoError> {

		let address = WAddress::from_parts(self.wid.as_ref().unwrap(),
		&self.domain.as_ref().unwrap());

		// Clear out storage database
		{
			let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
				rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
					Ok(v) => v,
					Err(e) => {
						return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
					}
				};
			
			let mut params = Vec::<String>::new();
			params.push(self.wid.as_ref().unwrap().to_string().clone());
			params.push(self.domain.as_ref().unwrap().to_string().clone());
			match get_string_from_db(&conn,
				"SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2", &params) {
				Ok(_) => (),
				Err(_) => { return Err(MensagoError::ErrNotFound) },
			}

			match conn.execute("DELETE FROM workspaces WHERE wid=?1 AND domain=?2",
				&[self.wid.as_ref().unwrap().as_string(), self.domain.as_ref().unwrap().as_string()]) {
				Ok(_) => (),
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}

			for table_name in ["folders", "sessions", "messages", "notes"] {

				match conn.execute(&format!("DELETE FROM {} WHERE address=?1", table_name),
					[address.as_string()]) {
					Ok(_) => (),
					Err(e) => {
						return Err(MensagoError::ErrDatabaseException(e.to_string()))
					}
				}
			}
		}

		// Clear out secrets database
		{
			let conn = match rusqlite::Connection::open_with_flags(&self.secretspath,
				rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
					Ok(v) => v,
					Err(e) => {
						return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
					}
				};

			match conn.execute("DELETE FROM keys WHERE address=?1", [address.as_string()]) {
				Ok(_) => (),
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}
		}

		Ok(())
	}

	/// Removes a workspace from the storage database. NOTE: This only removes the workspace entry
	/// itself. It does not remove keys, sessions, or other associated data.
	pub fn remove_workspace_entry(&self) -> Result<(), MensagoError> {

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};
		
		let mut params = Vec::<String>::new();
		params.push(self.wid.as_ref().unwrap().to_string().clone());
		params.push(self.domain.as_ref().unwrap().to_string().clone());
		match get_string_from_db(&conn,
			"SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2", &params) {
			Ok(_) => (),
			Err(_) => { return Err(MensagoError::ErrNotFound) },
		}

		match conn.execute("DELETE FROM workspaces WHERE wid=?1 AND domain=?2",
			&[self.wid.as_ref().unwrap().as_string(), self.domain.as_ref().unwrap().as_string()]) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		}

		Ok(())
	}
	

	/// Adds a mapping of a folder ID to a specific path in the workspace
	pub fn add_folder(&self, fmap: &FolderMap) -> Result<(), MensagoError> {

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
		};

		{
			let mut stmt = match conn.prepare("SELECT fid FROM folders WHERE fid=?1") {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
				
			let mut rows = match stmt.query([fmap.fid.as_string()]) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
	
			match rows.next() {
				Ok(optrow) => {
					match optrow {
						Some(_) => { return Err(MensagoError::ErrExists) },
						None => (),
					}
				},
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		}
	
		match conn.execute("INSERT INTO folders(fid,address,keyid,path,name,permissions)
			VALUES(?1,?2,?3,?4,?5,?6)",
			[fmap.fid.to_string(), fmap.address.to_string(), fmap.keyid.to_string(),
				fmap.path.to_string(), String::from(fmap.path.basename()), fmap.permissions.clone()]) {
			
			Ok(_) => { return Ok(()) },
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		}
	}

	/// Deletes a mapping of a folder ID to a specific path in the workspace
	pub fn remove_folder(&self, fid: &RandomID) -> Result<(), MensagoError> {

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
		};

		// Check to see if the folder ID passed to the function exists
		let mut stmt = match conn.prepare("SELECT fid FROM sessions WHERE fid=?1") {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};
			
		let mut rows = match stmt.query([fid.as_string()]) {
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
					Some(_) => (),
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

		match conn.execute("DELETE FROM folders WHERE fid=?1)", [fid.as_string()]) {
			
			Ok(_) => { return Ok(()) },
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		}
	}
	
	/// Gets the specified folder mapping.
	pub fn get_folder(self, fid: &RandomID) -> Result<FolderMap, MensagoError> {

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
		};
			
		// For the fully-commented version of this query, see profile::get_identity()
		let mut stmt = match conn
			.prepare("SELECT address,keyid,path,permissions FROM folders WHERE fid=?1") {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		
		let mut rows = match stmt.query([fid.as_string()]) {
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

		let waddr = match WAddress::from(&row.get::<usize,String>(0).unwrap()) {
			Some(v) => v,
			None => { return Err(MensagoError::ErrDatabaseException(
				String::from("Bad address in get_folder()")))}
		};

		let keyid = match CryptoString::from(&row.get::<usize,String>(1).unwrap()) {
			Some(v) => v,
			None => { return Err(MensagoError::ErrDatabaseException(
				String::from("Bad key ID in get_folder()")))}
		};

		let path = DBPath::from(&row.get::<usize,String>(2).unwrap())?;

		let fmap = FolderMap {
			fid: fid.clone(),
			address: waddr,
			keyid: keyid,
			path: path,
			permissions: String::from(&row.get::<usize,String>(3).unwrap()),
		};
		
		Ok(fmap)
	}
	
	/// Sets the human-friendly name for the workspace
	pub fn set_userid(&mut self, uid: &UserID) -> Result<(), MensagoError> {

		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};
		
		match conn.execute("UPDATE workspaces SET userid=?1 WHERE wid=?2 AND domain=?3",
			&[uid.as_string(), self.wid.as_ref().unwrap().as_string(),
			self.domain.as_ref().unwrap().as_string()]) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		}
		self.uid = Some(uid.clone());

		Ok(())
	}

	/// Gets the human-friendly name for the workspace
	pub fn get_userid(&self) -> Result<UserID, MensagoError> {

		match self.uid.as_ref() {
			Some(v) => return Ok(v.clone()),
			None => return Err(MensagoError::ErrEmptyData)
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	use eznacl::*;
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
		 let mut profile = match profman.create_profile("Primary") {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error creating profile 'Primary': {}", testname, e.to_string())))
			}
		 };

		profile.wid = RandomID::from("b5a9367e-680d-46c0-bb2c-73932a6d4007");
		profile.domain = Domain::from("example.com");
		match profile.activate() {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error activating profile 'Primary': {}", testname, e.to_string())))
			}
		}

		Ok(profman)
	}

	#[test]
	fn workspace_generate_and_db() -> Result<(), MensagoError> {

		// Because so much is needed to just set up a workspace test, we'll do a few tests in this
		// function:
		// - generate()
		// - add_to_db()
		// - remove_from_db()
		// - remove_workspace_entry()

		let testname = String::from("workspace_generate_and_db");
		let test_path = setup_test(&testname);

		let mut profman = setup_profile(&testname, &test_path)?;
		let mut profile = profman.get_active_profile_mut().unwrap();

		profile.wid = RandomID::from("b5a9367e-680d-46c0-bb2c-73932a6d4007");
		profile.domain = Domain::from("example.com");
		match profile.activate() {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error activating profile 'Primary': {}", testname, e.to_string())))
			}
		}

		// Hash of "CheeseCustomerSmugnessDelegatorGenericUnaudited"
		let pw = String::from("$argon2id$v=19$m=1048576,t=1,p=2$jc/H+Cn1NwJBJOTmFqAdlA$\
			b2zoU9ZNhHlo/ZYuSJwoqUAXEdf1cbN3fxmbQhP0zJc");

		let mut w = Workspace::new(&profile.path);
		match w.generate(&UserID::from("testname").unwrap(), profile.domain.as_ref().unwrap(),
			profile.wid.as_ref().unwrap(), &pw) {
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

		match w.remove_from_db() {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error removing workspace from db: {}", testname, e.to_string())))
			}
		}

		// Add again to test remove_workspace_entry()
		match w.add_to_db(&pwhash) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error re-adding workspace to db: {}", testname, e.to_string())))
			}
		}

		match w.remove_workspace_entry() {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error removing workspace entry: {}", testname, e.to_string())))
			}
		}

		Ok(())
	}

	#[test]
	fn workspace_folder() -> Result<(), MensagoError> {

		let testname = String::from("workspace_folder");
		let test_path = setup_test(&testname);

		let mut profman = setup_profile(&testname, &test_path)?;
		let mut profile = profman.get_profile_mut(0).unwrap();

		profile.wid = RandomID::from("b5a9367e-680d-46c0-bb2c-73932a6d4007");
		profile.domain = Domain::from("example.com");
		match profile.activate() {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error activating profile 'Primary': {}", testname, e.to_string())))
			}
		}

		let folderkey = eznacl::SecretKey::generate().unwrap();
		let fkeyhash = get_hash("SHA-256", folderkey.get_public_str().as_bytes())?;
		
		let w = Workspace::new(&profile.path);
		
		let foldermap = FolderMap{
			fid: RandomID::from("11111111-2222-3333-4444-555555666666").unwrap(),
			address: WAddress::from("aaaaaaaa-bbbb-cccc-dddd-eeeeeeffffff/example.com").unwrap(),
			keyid: fkeyhash.clone(),
			path: DBPath::from("/files/attachments").unwrap(),
			permissions: String::from("admin"),
		};

		// Case #1: Test add_folder
		match w.add_folder(&foldermap) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error adding folder mapping '/files/attachments': {}",
						 testname, e.to_string())))
			}
		}

		let conn = match rusqlite::Connection::open_with_flags(&w.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
		};
		// Check address
		match get_string_from_db(&conn,
			"SELECT address FROM folders WHERE fid=?1", &vec![foldermap.fid.to_string()]) {
			Ok(v) => {
				if v != foldermap.address.to_string() {
					return Err(MensagoError::ErrProgramException(format!(
						"test_dbpath: wanted {}, got {}", foldermap.address.to_string(), v)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error get folder mapping '/files/attachments': {}",
						 testname, e.to_string())))
			}
		}



		Ok(())
	}
}