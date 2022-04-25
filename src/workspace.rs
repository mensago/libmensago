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

	// TODO: Implement load_from_db()

	// TODO: Implement add_to_db()

	// TODO: Implement remove_from_db()

	// TODO: Implement remove_workspace_entry()

	// TODO: Implement add_folder()

	// TODO: Implement remove_folder()

	// TODO: Implement get_folder()

	// TODO: Implement set_userid()

	// TODO: Implement get_userid()
}
