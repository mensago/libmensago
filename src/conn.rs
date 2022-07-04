use crate::base::*;
use lazy_static::lazy_static;
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

lazy_static! {
	// Number of seconds to wait for a client before timing out
	static ref CONN_TIMEOUT: Duration = Duration::from_secs(1800);
}

// Size, in bytes, of the read buffer
const BUFFER_SIZE: usize = 16384;

#[derive(Debug)]
pub struct ServerConnection {
	socket: Option<TcpStream>,
	buffer: [u8; BUFFER_SIZE],
}

impl ServerConnection {

	/// Connects to a Mensago server given the specified address and port
	pub fn connect(&mut self, address: &str, port: &str) -> Result<(), MensagoError> {

		if address.len() == 0 || port.len() == 0 {
			return Err(MensagoError::ErrBadValue)
		}

		let mut sock =TcpStream::connect(format!("{}:{}", address, port))?;

		sock.set_read_timeout(Some(*CONN_TIMEOUT))?;

		// absorb the hello string for now
		sock.read(&mut self.buffer)?;

		// TODO: parse the hello string and get server version

		self.socket = Some(sock);

		Ok(())
	}
}
