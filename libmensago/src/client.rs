use crate::*;
use libkeycard::Domain;
use std::path::PathBuf;

/// The Client type primary interface to the entire library.
#[derive(Debug)]
pub struct Client {
	conn: Option<ServerConnection>,
	pman: ProfileManager,
	test_mode: bool,
}

impl Client {
	
	/// Instantiates a new Mensago client instance
	pub fn new(profile_folder: &str) -> Result<Client, MensagoError> {

		let mut pman = ProfileManager::new(&PathBuf::from(&profile_folder));
		pman.load_profiles(Some(&PathBuf::from(&profile_folder)))?;
		
		Ok(Client {
			conn: None,
			pman,
			test_mode: false,
		})
	}

	/// Places the client in test mode, which uses an offline DNS handler which points the client
	/// to localhost for communications. If the client is connected to a host, it will disconnect
	/// before changing.
	pub fn enable_test_mode(&mut self, use_test_mode: bool) {

		if self.is_connected() {
			self.disconnect()
		}
		self.test_mode = use_test_mode;
	}

	/// Establishes a network connection to a Mensago server. Logging in is not performed.
	pub fn connect(&mut self, domain: &Domain) -> Result<(), MensagoError> {

		if self.is_connected() {
			self.disconnect()
		}

		// TODO: finish client::connect()

		Err(MensagoError::ErrUnimplemented)
	}

	/// Returns true if the client is connected to a Mensago server.
	#[inline]
	pub fn is_connected(&self) -> bool {
		self.conn.is_some() && self.conn.as_ref().unwrap().is_connected()
	}

	pub fn disconnect(&mut self) {
		if self.is_connected() {
			self.conn.as_mut().unwrap().disconnect();
		}
	}

	// TODO: Finish implementing Client class. Depends on keycard resolver.
}