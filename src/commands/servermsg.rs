/// This module enables sending individual messages over a TcpStream connection. It operates under
/// the assumption that send and receive buffers are 64KiB in size. Messages which are bigger than 
/// this are broken up into chunks, sent to the remote host, and reassembled.
/// 
/// For the curious, the wire format uses a 1-byte type field and a 16-bit size field followed by
/// up to 65532 bytes of data.

/// Mensago commands originally used JSON both for the command format and for the data serialization
/// format, leading to a lot of character escaping. THis method keeps things lightweight and
/// eliminates all escaping.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream};
use std::time::Duration;
use crate::base::*;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
	static ref PACKET_SESSION_TIMEOUT: Duration = Duration::from_secs(30);
}

pub const MAX_MSG_SIZE: u16 = 65532;

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u8)]
enum FrameType {
	SingleFrame = 50,
	MultipartFrameStart = 51,
	MultipartFrame = 52,
	MultipartFrameFinal = 53,
	SessionSetupRequest = 54,
	SessionSetupResponse = 55,
	InvalidFrame = 255,
}

impl FrameType {
	
	// Creates a frame type from an integer value
	pub fn from(value: u8) -> FrameType {
		match value {
			50 => FrameType::SingleFrame,
			51 => FrameType::MultipartFrameStart,
			52 => FrameType::MultipartFrame,
			53 => FrameType::MultipartFrameFinal,
			54 => FrameType::SessionSetupRequest,
			55 => FrameType::SessionSetupResponse,
			_ => FrameType::InvalidFrame,
		}		
	}
}

// DataFrame is a structure for the lowest layer of network interaction. It represents a segment of
// data. Depending on the type code for the instance, it may indicate that
// the data payload is complete -- the SingleFrame type -- or it may be part of a larger set. In
// all cases a DataFrame is required to be equal to or smaller than the buffer size negotiated
// between the local host and the remote host.
#[derive(Debug)]
struct DataFrame {
	buffer: [u8; 65535],
	index: usize,
}

impl DataFrame {

	pub fn new() -> DataFrame {

		DataFrame {
			buffer: [0; 65535],
			index: 0,
		}
	}

	pub fn get_type(&self) -> FrameType {
		
		if self.buffer.len() > 0 {
			FrameType::from(self.buffer[0])
		} else {
			FrameType::InvalidFrame
		}
	}

	pub fn get_size(&self) -> usize {
		if self.index < 4 {
			return 0
		}

		self.index - 3
	}

	pub fn get_payload(&self) -> &[u8] {
		&self.buffer[3..self.index+1]
	}

	pub fn read(&mut self, conn: &mut TcpStream) -> Result<(), MensagoError> {

		// Invalidate the index in case we error out
		self.index = 0;

		let bytes_read = conn.read(&mut self.buffer)?;
		
		if bytes_read < 4 || FrameType::from(self.buffer[0]) == FrameType::InvalidFrame {
			return Err(MensagoError::ErrInvalidFrame)
		}

		// The size bytes are in network order (MSB), so this makes dealing with CPU architecture much
		// less of a headache regardless of what archictecture this is compiled for.
		let payload_size = (u16::from(self.buffer[1]) << 8) + u16::from(self.buffer[2]);
		if bytes_read != usize::from(payload_size) + 3 {
			return Err(MensagoError::ErrSize)
		}
		self.index = bytes_read-1;

		Ok(())
	}
}

/// Writes a DataFrame to a network connection. The payload may not be any larger than 65532 bytes.
fn write_frame(conn: &mut TcpStream, ftype: FrameType, payload: &[u8]) -> Result<(), MensagoError> {
	
	let paylen = payload.len() as u16;

	if payload.len() > 65532 {
		return Err(MensagoError::ErrSize)
	}
	conn.write(&[
		ftype as u8,
		((paylen >> 8) & 255) as u8,
		(paylen & 255) as u8,
	])?;
	conn.write(payload)?;
	
	Ok(())
}

/// Reads an arbitrarily-sized message from a socket and returns it
pub fn read_message(conn: &mut TcpStream) -> Result<Vec::<u8>, MensagoError> {

	let mut out = Vec::<u8>::new();
	let mut chunk = DataFrame::new();

	chunk.read(conn)?;

	match chunk.get_type() {
		FrameType::SingleFrame => {
			out.extend_from_slice(chunk.get_payload());
			return Ok(out)
		},
		FrameType::MultipartFrameStart => (),
		FrameType::MultipartFrameFinal | FrameType::MultipartFrame => {
			return Err(MensagoError::ErrBadSession)
		},
		_ => {
			return Err(MensagoError::ErrInvalidFrame)
		}
	}
	
	// We got this far, so we have a multipart message which we need to reassemble.

	// No validity checking is performed on the actual data in a DataFrame, so we need to validate
	// the total payload size. Note that payload of a MultipartFrameStart frame is a string which
	// contains the size of the total payload. This seems a bit silly, but
	let sizestr = match String::from_utf8(chunk.get_payload().to_vec()) {
		Ok(v) => v,
		Err(_) => {
			return Err(MensagoError::ErrInvalidFrame)
		}
	};
	let totalsize = match sizestr.parse::<usize>() {
		Ok(v) => v,
		Err(_) => {
			return Err(MensagoError::ErrInvalidFrame)
		}
	};

	
	let mut sizeread: usize = 0;
	while sizeread < totalsize {
		chunk.read(conn)?;

		out.extend_from_slice(chunk.get_payload());
		sizeread += chunk.get_size();

		if chunk.get_type() == FrameType::MultipartFrameFinal {
			break
		}
	}

	if sizeread != totalsize {
		return Err(MensagoError::ErrSize)
	}

	Ok(out)
}

/// Writes an arbitrarily-sized message to a socket
pub fn write_message(conn: &mut TcpStream, msg: &[u8]) -> Result<(), MensagoError> {

	if msg.len() == 0 {
		return Err(MensagoError::ErrSize)
	}

	// If the packet is small enough to fit into a single frame, just send it and be done.
	if msg.len() < usize::from(MAX_MSG_SIZE) {
		return write_frame(conn, FrameType::SingleFrame, msg)
	}

	// If the message is bigger than the max message length, then we will send it as a multipart
	// message. This takes more work internally, but the benefits at the application level are
	// worth it. By using a binary wire format, we don't have to deal with serialization, escaping
	// and all sorts of other complications.

	// The initial message indicates that it is the start of a multipart message and contains the
	// total size in the payload as a string. All messages that follow contain the actual message
	// data.

	write_frame(conn, FrameType::MultipartFrameStart, msg.len().to_string().as_bytes())?;
	
	let mut index: usize = 0;
	let maxmsgsize = usize::from(MAX_MSG_SIZE);
	while index+maxmsgsize < msg.len() {
		write_frame(conn, FrameType::MultipartFrame, &msg[index..index+maxmsgsize])?;
		index += maxmsgsize;
	}

	write_frame(conn, FrameType::MultipartFrameFinal, &msg[index..])
}

/// ClientRequest is a data structure used to represent a Mensago command, such as LOGIN or GETWID.
/// It is not part of the library's public API because the command functions are intended to
/// provide a much better developer experience and integrate with other Rust code better.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientRequest {
	pub action: String,
	pub data: HashMap<String, String>
}

impl ClientRequest {

	/// Creates a new ClientRequest
	pub fn new(action: &str) -> ClientRequest {
		ClientRequest {
			action: String::from(action),
			data: HashMap::<String, String>::new(),
		}
	}

	/// Creates a new ClientRequest and attaches some data
	pub fn from(action: &str, data: &[(&str, &str)]) -> ClientRequest {
		let mut out = ClientRequest::new(action);
		for pair in data {
			out.data.insert(String::from(pair.0), String::from(pair.1));
		}

		out
	}

	/// Converts the ClientRequest to JSON and sends to the server
	pub fn send(&self, conn: &mut TcpStream) -> Result<(), MensagoError> {
		write_message(conn, serde_json::to_string(&self)?.as_bytes())
	}
}

/// ServerResponse holds information received as a response to a client request. The `code` field
/// holds an integer for easy comparisons and a status string for human interpretation where
/// required. The `info` field is used by the server to offer more insight as to why an error was
/// received. Any return data from a command is kept in the `data` field and will be specific to
/// the individual command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerResponse {
	pub status: CmdStatus,
	pub data: HashMap<String, String>
}

impl ServerResponse {

	/// Reads a ServerResponse from the connection
	pub fn receive(conn: &mut TcpStream) -> Result<ServerResponse, MensagoError> {
		
		let rawdata = read_message(conn)?;
		let rawjson = match String::from_utf8(rawdata) {
			Ok(v) => v,
			Err(_) => { return Err(MensagoError::ErrBadMessage) }
		};
		let msg: ServerResponse = match serde_json::from_str(&rawjson) {
			Ok(v) => v,
			Err(_) => { return Err(MensagoError::ErrBadMessage) }
		};

		Ok(msg)
	}

	/// Checks attached data for the requested fields in the fieldinfo tuple. The bool parameter is
	/// for specifying if the field is required. Returns true if all required fields are present.
	pub fn check_fields(&self, fieldinfo: &[(&str, bool)]) -> bool {

		for info in fieldinfo {
			if self.data.get(info.0).is_none() && info.1 == true {
				return false
			}
		}
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::{TcpListener,TcpStream};
	use std::sync::mpsc::channel;
	use std::time::Duration;
	use std::thread;

	// test_frame_session and its corresponding setup function cover session setup and transmitting
	// and receiving a single frame over the wire
	#[test]
	fn test_frame_session() -> Result<(), MensagoError> {
		let testname = String::from("test_frame_session");

		// Use a channel for synchronization
		let (sender, receiver) = channel::<u8>();

		let listener = TcpListener::bind("127.0.0.1:2999")?;

		let thandle = thread::spawn(move || {
			let _ = receiver.recv().unwrap();

			thread::sleep(Duration::from_millis(100));
			
			let mut senderconn = match TcpStream::connect("127.0.0.1:2999") {
				Ok(v) => v,
				Err(e) => {
					print!("test_frame_session: error creating thread socket: {}", e.to_string());
					panic!("")
				}
			};

			let msg = "ThisIsATestMessage";
			match write_message(&mut senderconn, msg.as_bytes()) {
				Ok(_) => (),
				Err(e) => {
					print!("test_frame_session: error thread writing msg: {}", e.to_string());
					panic!("")
				}
			}

		});
		
		// Send data over the channel to unblock the sender thread
		match sender.send(0) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error unblocking sender thread: {}", testname, e.to_string())
				))
			}
		}
		
		let (mut receiverconn, _) = listener.accept()?;
		let rawdata = read_message(&mut receiverconn)?;
		let msgstr = String::from_utf8(rawdata).unwrap();
		
		if msgstr != "ThisIsATestMessage" {
			return Err(MensagoError::ErrProgramException(
				format!("{}: data mismatch error: got '{}'", testname, msgstr)
			))
		}

		thandle.join().unwrap();
		Ok(())
	}

	#[test]
	fn test_write_multipart_msg() -> Result<(), MensagoError> {

		// TODO: Implement test_write_multipart_msg()

		Ok(())
	}

	#[test]
	fn test_read_multipart_msg() -> Result<(), MensagoError> {

		// TODO: Implement test_read_multipart_msg()

		Ok(())
	}
}

