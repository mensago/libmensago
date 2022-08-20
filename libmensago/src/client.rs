use crate::*;
use std::path::PathBuf;

/// The Client type primary interface to the entire library.
#[derive(Debug)]
pub struct Client {
	conn: Option<ServerConnection>,
	pman: ProfileManager,
}

impl Client {
	
	pub fn new(profile_folder: &str) -> Result<Client, MensagoError> {

		let mut pman = ProfileManager::new(&PathBuf::from(&profile_folder));
		pman.load_profiles(Some(&PathBuf::from(&profile_folder)))?;
		
		Ok(Client {
			conn: None,
			pman: pman,
		})
	}

	// TODO: Finish implementing Client class. Depends on keycard resolver.
}