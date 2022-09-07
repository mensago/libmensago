use crate::*;
use eznacl::EncryptionKey;
use libkeycard::*;
use std::path::PathBuf;

/// The Client type primary interface to the entire library.
#[derive(Debug)]
pub struct Client {
	conn: ServerConnection,
	pman: ProfileManager,
	test_mode: bool,
	is_admin: bool,
	login_active: bool,
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
			is_admin: false,
			login_active: false,
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

		_ = self.disconnect();

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

	/// Gracefully closes a connection with a Mensago server.
	pub fn disconnect(&mut self) -> Result<(), MensagoError> {

		if self.is_connected() {
			self.conn.disconnect()
		} else {
			Ok(())
		}
	}

	/// Logs into a server. Note that while logging in and connecting are not the same, if this
	/// call is made while not connected to a server, an attempt to connect will be made.
	pub fn login(&mut self, address: &MAddress) -> Result<(), MensagoError> {
		if !self.is_connected() {
			self.connect(address.get_domain())?;
		}

		let mut dh: Box<dyn DNSHandlerT> = if self.test_mode {
			Box::<FakeDNSHandler>::new(FakeDNSHandler::new())
		} else {
			Box::<DNSHandler>::new(DNSHandler::new_default()?)
		};

		let record = get_mgmt_record(address.get_domain(), dh.as_mut())?;
		let profile = match self.pman.get_active_profile() {
			Some(v) => v,
			None => {
				return Err(MensagoError::ErrNoProfile)
			}
		};

		let waddr = match address.get_uid().get_type() {
			IDType::WorkspaceID => {
				WAddress::from_maddress(&address).unwrap()
			},
			IDType::UserID => {
				let mut resolver = KCResolver::new(&profile)?;
				let wid = resolver.resolve_address(&address, dh.as_mut())?;
				WAddress::from_parts(&wid, address.get_domain())
			},
		};
		
		let serverkey = EncryptionKey::from(&record.ek)?;
		login(&mut self.conn, waddr.get_wid(), &serverkey)?;

		let secrets = open_secrets_db(&profile)?;
		let passhash = get_credentials(&secrets, &waddr)?;
		password(&mut self.conn, &passhash)?;
		
		let devpair = get_session_keypair(&secrets, &waddr)?;
		self.is_admin = device(&mut self.conn, waddr.get_wid(), &devpair)?;

		Ok(())
	}

	/// Returns true if the client is connected to an active login session
	pub fn is_logged_in(&mut self) -> bool {
		if self.is_connected() {
			return self.login_active;
		}
		self.login_active = false;
		return false;
	}

	/// Returns true if the client is connected to an active login session and the user has
	/// administrator rights in the session.
	pub fn is_admin(&mut self) -> bool {
		return self.is_logged_in() && self.is_admin
	}

	/// Logs out of any active login sessions. This does not disconnect from the server itself;
	/// instead it reverts the session to an unauthenticated state.
	pub fn logout(&mut self) -> Result<(), MensagoError> {
		self.login_active = false;
		self.is_admin = false;
		if self.is_connected() {
			logout(&mut self.conn)
		} else {
			Ok(())
		}
	}

	// TODO: Finish implementing Client class. Depends on keycard resolver.
}