use crate::*;
use libkeycard::Domain;
use std::path::PathBuf;

/// The Client type primary interface to the entire library.
#[derive(Debug)]
pub struct Client {
	conn: ServerConnection,
	pman: ProfileManager,
	test_mode: bool,
}

impl Client {
	
	/// Instantiates a new Mensago client instance
	pub fn new(profile_folder: &str) -> Result<Client, MensagoError> {

		let mut pman = ProfileManager::new(&PathBuf::from(&profile_folder));
		pman.load_profiles(Some(&PathBuf::from(&profile_folder)))?;
		
		Ok(Client {
			conn: ServerConnection::new(),
			pman,
			test_mode: false,
		})
	}

	/// Places the client in test mode, which uses an offline DNS handler which points the client
	/// to localhost for communications. If the client is connected to a host, it will disconnect
	/// before changing.
	pub fn enable_test_mode(&mut self, use_test_mode: bool) {

		if self.is_connected() {
			_ = self.disconnect();
		}
		self.test_mode = use_test_mode;
	}

	/// Establishes a network connection to a Mensago server. Logging in is not performed.
	pub fn connect(&mut self, domain: &Domain) -> Result<(), MensagoError> {

		self.disconnect();

		if self.test_mode {
			let mut dh = FakeDNSHandler::new();
			let serverconfig = get_server_config(domain, &mut dh)?;
			if serverconfig.len() == 0 {
				return Err(MensagoError::ErrNotFound)
			}
			let ip = dh.lookup_a(&serverconfig[0].server)?;
			self.conn.connect(&ip.to_string(), serverconfig[0].port)
		} else {
			let mut dh = DNSHandler::new_default()?;
			let serverconfig = get_server_config(domain, &mut dh)?;
			if serverconfig.len() == 0 {
				return Err(MensagoError::ErrNotFound)
			}
			let ip = dh.lookup_a(&serverconfig[0].server)?;
			self.conn.connect(&ip.to_string(), serverconfig[0].port)
		}
	}

	/// Returns true if the client is connected to a Mensago server.
	#[inline]
	pub fn is_connected(&self) -> bool {
		self.conn.is_connected()
	}

	pub fn disconnect(&mut self) -> Result<(), MensagoError> {

		if self.is_connected() {
			self.conn.disconnect()
		} else {
			Ok(())
		}
	}

	// TODO: Finish implementing Client class. Depends on keycard resolver.
}