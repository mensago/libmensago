use std::path::PathBuf;
use crate::base::*;
use crate::types::*;

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
