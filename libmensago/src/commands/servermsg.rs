use crate::base::*;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
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
use std::time::Duration;

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

    // This method only works for frames with the type MultipartFrameStart. It returns the size of
    // the multipart message data to follow.
    pub fn get_multipart_size(&self) -> Result<usize, MensagoError> {
        if self.get_size() < 1 {
            return Err(MensagoError::ErrInvalidFrame);
        }

        if FrameType::from(self.buffer[0]) != FrameType::MultipartFrameStart {
            return Err(MensagoError::ErrTypeMismatch);
        }

        let valstring = String::from_utf8(self.get_payload().to_vec())?;
        let totalsize = match valstring.parse::<usize>() {
            Ok(v) => v,
            Err(_) => return Err(MensagoError::ErrBadValue),
        };
        Ok(totalsize)
    }

    pub fn get_size(&self) -> usize {
        if self.index < 4 {
            return 0;
        }

        self.index - 3
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.buffer[3..self.index]
    }

    pub fn read<R: Read>(&mut self, conn: &mut R) -> Result<(), MensagoError> {
        // Invalidate the index in case we error out
        self.index = 0;

        // Check how much should be waiting for us
        let bytes_read = match conn.read(&mut self.buffer[..3]) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };

        if bytes_read < 3 || FrameType::from(self.buffer[0]) == FrameType::InvalidFrame {
            return Err(MensagoError::ErrInvalidFrame);
        }

        // The size bytes are in network order (MSB), so this makes dealing with CPU architecture
        // much less of a headache regardless of what archictecture this is compiled for.
        let payload_size = (u16::from(self.buffer[1]) << 8) + u16::from(self.buffer[2]);

        let bytes_read = match conn.read(&mut self.buffer[3..usize::from(3 + payload_size)]) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };
        if bytes_read != usize::from(payload_size) {
            return Err(MensagoError::ErrSize);
        }
        self.index = bytes_read + 3;

        Ok(())
    }
}

/// Writes a DataFrame to a network connection. The payload may not be any larger than 65532 bytes.
fn write_frame<W: Write>(
    conn: &mut W,
    ftype: FrameType,
    payload: &[u8],
) -> Result<(), MensagoError> {
    let paylen = payload.len() as u16;

    if payload.len() > 65532 {
        return Err(MensagoError::ErrSize);
    }
    match conn.write(&[
        ftype as u8,
        ((paylen >> 8) & 255) as u8,
        (paylen & 255) as u8,
    ]) {
        Ok(v) => v,
        Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
    };
    match conn.write(payload) {
        Ok(v) => v,
        Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
    };

    Ok(())
}

/// Reads an arbitrarily-sized message from an IO::Read and returns it
pub fn read_message<R: Read>(conn: &mut R) -> Result<Vec<u8>, MensagoError> {
    let mut out = Vec::<u8>::new();
    let mut chunk = DataFrame::new();

    chunk.read(conn)?;

    match chunk.get_type() {
        FrameType::SingleFrame => {
            out.extend_from_slice(chunk.get_payload());
            return Ok(out);
        }
        FrameType::MultipartFrameStart => (),
        FrameType::MultipartFrameFinal | FrameType::MultipartFrame => {
            return Err(MensagoError::ErrBadSession)
        }
        _ => return Err(MensagoError::ErrInvalidFrame),
    }

    // We got this far, so we have a multipart message which we need to reassemble.

    let totalsize = chunk.get_multipart_size()?;

    let mut sizeread: usize = 0;
    while sizeread < totalsize {
        chunk.read(conn)?;

        out.extend_from_slice(chunk.get_payload());
        sizeread += chunk.get_size();

        if chunk.get_type() == FrameType::MultipartFrameFinal {
            break;
        }
    }

    if sizeread != totalsize {
        return Err(MensagoError::ErrSize);
    }

    Ok(out)
}

/// Reads a message as per `read_message()` but returns the data as a string
pub fn read_str_message<R: Read>(conn: &mut R) -> Result<String, MensagoError> {
    let rawdata = read_message(conn)?;
    Ok(String::from_utf8(rawdata)?)
}

/// Writes an arbitrarily-sized message to an IO::Write
pub fn write_message<W: Write>(conn: &mut W, msg: &[u8]) -> Result<(), MensagoError> {
    if msg.len() == 0 {
        return Err(MensagoError::ErrSize);
    }

    // If the packet is small enough to fit into a single frame, just send it and be done.
    if msg.len() < usize::from(MAX_MSG_SIZE) {
        return write_frame(conn, FrameType::SingleFrame, msg);
    }

    // If the message is bigger than the max message length, then we will send it as a multipart
    // message. This takes more work internally, but the benefits at the application level are
    // worth it. By using a binary wire format, we don't have to deal with serialization, escaping
    // and all sorts of other complications.

    // The initial message indicates that it is the start of a multipart message and contains the
    // total size in the payload as a string. All messages that follow contain the actual message
    // data.

    write_frame(
        conn,
        FrameType::MultipartFrameStart,
        msg.len().to_string().as_bytes(),
    )?;

    let mut index: usize = 0;
    let maxmsgsize = usize::from(MAX_MSG_SIZE);
    while index + maxmsgsize < msg.len() {
        write_frame(
            conn,
            FrameType::MultipartFrame,
            &msg[index..index + maxmsgsize],
        )?;
        index += maxmsgsize;
    }

    write_frame(conn, FrameType::MultipartFrameFinal, &msg[index..])
}

/// ClientRequest is a data structure used to represent a Mensago command, such as LOGIN or GETWID.
/// It is not part of the library's public API because the command functions are intended to
/// provide a much better developer experience and integrate with other Rust code better.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientRequest {
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Data")]
    pub data: HashMap<String, String>,
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
    pub fn send<W: Write>(&self, conn: &mut W) -> Result<(), MensagoError> {
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
    #[serde(rename = "Code")]
    pub code: u16,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Info")]
    pub info: String,
    #[serde(rename = "Data")]
    pub data: HashMap<String, String>,
}

impl ServerResponse {
    /// Reads a ServerResponse from the connection
    pub fn receive<R: Read>(conn: &mut R) -> Result<ServerResponse, MensagoError> {
        let rawjson = match read_str_message(conn) {
            Ok(v) => v,
            Err(_) => return Err(MensagoError::ErrBadMessage),
        };
        let msg: ServerResponse = serde_json::from_str(&rawjson)?;

        Ok(msg)
    }

    /// Checks attached data for the requested fields in the fieldinfo tuple. The bool parameter is
    /// for specifying if the field is required. Returns true if all required fields are present.
    pub fn check_fields(&self, fieldinfo: &[(&str, bool)]) -> bool {
        for info in fieldinfo {
            if self.data.get(info.0).is_none() && info.1 == true {
                return false;
            }
        }
        true
    }

    /// Returns a CmdStatus object based on the contents of the server response
    pub fn as_status(&self) -> CmdStatus {
        return CmdStatus {
            code: self.code,
            description: self.status.clone(),
            info: self.info.clone(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iobuffer::IoBuffer;

    #[test]
    fn test_frame_get_methods() -> Result<(), MensagoError> {
        let testname = String::from("test_frame_get_methods");

        let data: [u8; 7] = [50, 0, 4, 65, 66, 67, 68];

        let mut conn = IoBuffer::new();
        match conn.write(&data) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };

        let mut frame = DataFrame::new();
        frame.read(&mut conn)?;

        if frame.get_size() != 4 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: get_size() returned {} instead of 4",
                testname,
                frame.get_size()
            )));
        }

        let pstr = String::from_utf8(frame.get_payload().to_vec())?;
        if pstr != "ABCD" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: payload mismatch {} instead of 'ABCD'",
                testname, pstr
            )));
        }

        Ok(())
    }

    // test_frame_session and its corresponding setup function cover session setup and transmitting
    // and receiving a single frame over the wire
    #[test]
    fn test_frame_session() -> Result<(), MensagoError> {
        let testname = String::from("test_frame_session");

        let mut conn = IoBuffer::new();

        let msg = "ThisIsATestMessage";
        match write_message(&mut conn, msg.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                print!(
                    "test_frame_session: error thread writing msg: {}",
                    e.to_string()
                );
                panic!("")
            }
        }

        let msgstr = read_str_message(&mut conn)?;

        if msgstr != "ThisIsATestMessage" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: data mismatch error: got '{}'",
                testname, msgstr
            )));
        }

        Ok(())
    }

    // This test works by creating a message that is a little bigger than 64K, forcing
    // write_message() to create 3 frames: a start frame, a middle frame, and a final one. There is
    // no real limit to how big of an actual message can be sent outside of physical resources, but
    // it does have to be send in 65532-byte chunks.
    #[test]
    fn test_write_multipart_msg() -> Result<(), MensagoError> {
        let testname = String::from("test_write_multipart_msg");

        let mut conn = IoBuffer::new();

        let sentmsg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(2601);
        match write_message(&mut conn, sentmsg.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error writing msg: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let mut frame = DataFrame::new();
        frame.read(&mut conn)?;

        // First, get the first data frame, which should be of type MultipartMessageStart and the
        // payload should contain a decimal string of the size of the complete message size.
        let totalsize = match frame.get_multipart_size() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting total size: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        if totalsize != sentmsg.len() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: total size mismatch: {}",
                testname, totalsize
            )));
        }

        let mut msgparts = Vec::<u8>::new();

        // Now get and process the first actual data frame
        frame.read(&mut conn)?;
        if frame.get_type() != FrameType::MultipartFrame {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: first data frame had wrong type",
                testname
            )));
        }
        msgparts.extend_from_slice(frame.get_payload());

        // Finally deal with the final frame
        frame.read(&mut conn)?;
        if frame.get_type() != FrameType::MultipartFrameFinal {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: final frame had wrong type",
                testname
            )));
        }
        msgparts.extend_from_slice(frame.get_payload());

        // Message data received from both data frames and complete. Now reassemble, check total
        // size, and confirm value match.

        let receivedmsg = String::from_utf8(msgparts.to_vec())?;
        if sentmsg.len() != receivedmsg.len() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: message size mismatch: {} vs {}",
                testname,
                sentmsg.len(),
                receivedmsg.len()
            )));
        }
        if sentmsg != receivedmsg {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: message mismatch",
                testname
            )));
        }

        Ok(())
    }

    #[test]
    fn test_read_multipart_msg() -> Result<(), MensagoError> {
        let testname = String::from("test_read_multipart_msg");

        let mut conn = IoBuffer::new();

        let sentmsg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(2601);
        match write_message(&mut conn, sentmsg.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error writing msg: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let receivedmsg = read_str_message(&mut conn)?;
        if sentmsg.len() != receivedmsg.len() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: message size mismatch: {} vs {}",
                testname,
                sentmsg.len(),
                receivedmsg.len()
            )));
        }
        if sentmsg != receivedmsg {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: message mismatch",
                testname
            )));
        }

        Ok(())
    }
}
