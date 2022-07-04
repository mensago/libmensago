// This module implements the data serialization for the client-server commands using a new
// lightweight self-documenting binary format called JBinPack. JBinPack was inspired by the
// Netstring format. Because Mensago communications are UTF-8 text-based, this module uses only a
// part of the format: messages are sent as String or BigString. String supports data up to 64KiB,
// which easily accommodates regular Mensago commands. Bulk data uploads and downloads are handled
// with HugeString, which can accommodate individual file sizes of up to 16EiB.
//
// The String format consists of a 1-byte value 14, a 2-byte MSB-order length code, and the
// data follows. The string "ABC123" would be encoded as `0e 00 06 41 42 43 31 32 33`.
//
// The HugeString format consists of a 1-byte value 14, an 8-byte MSB-order length code, and the
// data follows. The string "ABC123" encoded as a HugeString would be encoded similar to the above: 
// `10 00 00 00 00 00 00 00 06 41 42 43 31 32 33`.
//
// Mensago commands originally used JSON both for the command format and for the data serialization
// format, leading to a lot of character escaping. Using JBinPack for data serialization keeps
// things lightweight and eliminates all escaping. If the need to send binary data over the wire
// were needed at some point in the future, literally the only change needed would be the type
// codes.
use crate::base::*;
use std::io::Read;
use std::net::TcpStream;

#[derive(Debug, PartialEq, PartialOrd)]
enum FrameType {
	SingleFrame,
	MultipartFrameStart,
	MultipartFrame,
	MultipartFrameFinal,
	SessionSetupRequest,
	SessionSetupResponse,
	InvalidFrame,
}

impl FrameType {
	
	// Converts a frame type to the integer value sent over the wire
	pub fn to_value(&self) -> u8 {
		match self {
			FrameType::SingleFrame => 50,
			FrameType::MultipartFrameStart => 51,
			FrameType::MultipartFrame => 52,
			FrameType::MultipartFrameFinal => 53,
			FrameType::SessionSetupRequest => 54,
			FrameType::SessionSetupResponse => 55,
			_ => 255,
		}
	}

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
	buffer: Vec::<u8>,
	index: usize,
}

impl DataFrame {

	pub fn new(bufferSize: usize) -> Option<DataFrame> {

		if bufferSize < 1024 {
			return None
		}

		Some(DataFrame {
			buffer: Vec::<u8>::new(),
			index: 0,
		})
	}

	pub fn get_type(&self) -> FrameType {
		
		if self.buffer.len() > 0 {
			FrameType::from(self.buffer[0])
		} else {
			FrameType::InvalidFrame
		}
	}

	pub fn get_size(&self) -> usize {
		if self.buffer.len() < 4 {
			return 0
		}

		self.buffer.len() - 3
	}

	pub fn get_payload(&self) -> &[u8] {
		&self.buffer[3..]
	}

	pub fn get_payload_mut(&mut self) -> &[u8] {
		&mut self.buffer[3..self.index]
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
		self.index = bytes_read;

		Ok(())
	}
}

