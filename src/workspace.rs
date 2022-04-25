use std::path::PathBuf;
use crate::auth;
use crate::base::*;
use crate::types::*;
use eznacl::{ EncryptionPair, SigningPair, PublicKey, PrivateKey };

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct Workspace {
	dbpath: PathBuf,
	path: PathBuf,
	uid: Option<UserID>,
	wid: Option<RandomID>,
	domain: Option<Domain>,
	_type: String,
	pw: String,
}

impl Workspace {

	/// Creates a new, uninitialized Workspace object
	pub fn new(dbpath: &PathBuf, path: &PathBuf) -> Workspace {

		return Workspace{
			dbpath: dbpath.clone(),
			path: path.clone(),
			uid: None,
			wid: None,
			domain: None,
			_type: String::from("identity"),
			pw: String::from(""),
		}
	}

	/// Creates all the data needed for an individual workspace account
	pub fn generate(&mut self, uid: &UserID, server: &Domain, wid: &RandomID, pw: &str) 
		-> Result<(),MensagoError> {
		
		self.uid = Some(uid.clone());
		self.wid = Some(wid.clone());
		self.domain = Some(server.clone());
		self.pw = String::from(pw);

		let address = MAddress::from_parts(&UserID::from_wid(wid), server);
		let waddr = WAddress::from_parts(&wid, &server);
		
		let conn = match rusqlite::Connection::open_with_flags(&self.dbpath,
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
		
		// TODO: Finish implementing Workspace::generate()

		Err(MensagoError::ErrUnimplemented)
	}

	/// Loads the workspace information from the local database. If no workspace ID is specified,
	/// the identity workspace for the profile is loaded.
	pub fn load_from_db(&mut self, waddr: Option<RandomID>) -> Result<(), MensagoError> {

		// TODO: Implement load_from_db()

		Err(MensagoError::ErrUnimplemented)
	}

	/// Adds a workspace to the storage database
	pub fn add_to_db(&self, pw: &ArgonHash) -> Result<(), MensagoError> {

		// TODO: Implement add_to_db()

		Err(MensagoError::ErrUnimplemented)
	}

	/// Removes ALL DATA associated with a workspace. Don't call this unless you mean to erase all
	/// evidence that a particular workspace ever existed.
	pub fn remove_from_db(&self) -> Result<(), MensagoError> {

		// TODO: Implement remove_from_db()

		Err(MensagoError::ErrUnimplemented)
	}

	/// Removes a workspace from the storage database. NOTE: This only removes the workspace entry
	/// itself. It does not remove keys, sessions, or other associated data.
	pub fn remove_workspace_entry() -> Result<(), MensagoError> {

		// TODO: Implement remove_workspace_entry()

		Err(MensagoError::ErrUnimplemented)
	}
	

	// /// Adds a mapping of a folder ID to a specific path in the workspace
	// pub fn add_folder(&self, fid: FolderMap) -> Result<(), MensagoError> {

	// 	// TODO: Implement add_folder() once the DBFS layer is implemented

	// 	Err(MensagoError::ErrUnimplemented)
	// }

	/// Deletes a folder mapping
	pub fn remove_folder(&self, fid: &RandomID) -> Result<(), MensagoError> {

		// TODO: Implement remove_folder()
		
		Err(MensagoError::ErrUnimplemented)
	}
	
	// /// Gets the specified folder mapping.
	// pub fn get_folder(self, fid: &RandomID) -> Result<FolderMap, MensagoError> {

	// 	// TODO: Implement get_folder() once the DBFS layer is implemented

	// 	Err(MensagoError::ErrUnimplemented)
	// }
	
	/// Sets the human-friendly name for the workspace
	pub fn set_userid(&mut self, uid: &UserID) -> Result<(), MensagoError> {

		// TODO: Implement set_userid()
		
		Err(MensagoError::ErrUnimplemented)
	}

	/// Gets the human-friendly name for the workspace
	pub fn get_userid(&self) -> Result<UserID, MensagoError> {

		// TODO: Implement get_userid()
		
		Err(MensagoError::ErrUnimplemented)
	}
}
