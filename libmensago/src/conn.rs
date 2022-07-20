use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;
use crate::base::*;
use crate::commands::*;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
	// Number of seconds to wait for a client before timing out
	static ref CONN_TIMEOUT: Duration = Duration::from_secs(1800);
}

// Size, in bytes, of the read buffer
const BUFFER_SIZE: usize = 16384;

#[derive(Debug, Serialize, Deserialize)]
struct GreetingData {
	#[serde(rename="Name")]
	name: String,
	#[serde(rename="Version")]
	version: String,
	#[serde(rename="Code")]
	code: u16,
	#[serde(rename="Status")]
	status: String,
	#[serde(rename="Date")]
	date: String,
}

#[derive(Debug)]
pub struct ServerConnection {
	socket: Option<TcpStream>,
	buffer: [u8; BUFFER_SIZE],
}

impl ServerConnection {
	pub fn new() -> ServerConnection {
		ServerConnection{ socket: None, buffer: [0; BUFFER_SIZE] }
	}

	/// Connects to a Mensago server given the specified address and port
	pub fn connect(&mut self, address: &str, port: &str) -> Result<(), MensagoError> {

		if address.len() == 0 || port.len() == 0 {
			return Err(MensagoError::ErrBadValue)
		}

		let mut sock =TcpStream::connect(format!("{}:{}", address, port))?;

		sock.set_read_timeout(Some(*CONN_TIMEOUT))?;

		// absorb the hello string for now
		let bytes_read = sock.read(&mut self.buffer)?;

		let rawjson = match String::from_utf8(self.buffer[..bytes_read].to_vec()) {
			Ok(v) => v,
			Err(_) => { return Err(MensagoError::ErrBadMessage) }
		};
		let greeting: GreetingData = match serde_json::from_str(&rawjson.trim()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("error parsing server greeting: {}", e.to_string())
				))
			}
		};

		if greeting.code != 200 {
			return Err(MensagoError::ErrProtocol(CmdStatus {
				code: greeting.code,
				description: greeting.status,
				info: String::new(),
			}))
		}

		self.socket = Some(sock);

		Ok(())
	}

	/// Returns true if connected to a server
	#[inline]
	pub fn is_connected(&self) -> bool {
		self.socket.is_some()
	}

	/// Disconnects from the server by sending a QUIT command to the server and then closing the 
	/// TCP session
	pub fn disconnect(&mut self) -> Result<(), MensagoError> {
		match self.socket {
			Some(_) => { quit(self.socket.as_mut().unwrap()) },
			None => Ok(()),
		}
	}

	pub fn receive(&mut self) -> Result<ServerResponse, MensagoError> {
		if self.socket.is_none() {
			return Err(MensagoError::ErrNotConnected)
		}
		ServerResponse::receive(self.socket.as_mut().unwrap())
	}

	pub fn send(&mut self, msg: &ClientRequest) -> Result<(), MensagoError> {
		if self.socket.is_none() {
			return Err(MensagoError::ErrNotConnected)
		}
		msg.send(self.socket.as_mut().unwrap())
	}
}
