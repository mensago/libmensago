use crate::base::*;
use crate::commands::*;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::TcpStream;
use std::time::Duration;

lazy_static! {
    // Number of seconds to wait for a client before timing out
    static ref CONN_TIMEOUT: Duration = Duration::from_secs(1800);
}

// Size, in bytes, of the read buffer
const BUFFER_SIZE: usize = 65535;

#[derive(Debug, Serialize, Deserialize)]
struct GreetingData {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Code")]
    code: u16,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Date")]
    date: String,
}

/// The MConn trait is for any type which implements the methods needed for connecting to a
/// Mensago server. It exists mostly for an abstraction to make testing easier.
pub trait MConn {
    /// Connects to a Mensago server
    fn connect(&mut self, address: &str, port: u16) -> Result<(), MensagoError>;

    /// Gracefully disconnects from a Mensago server
    fn disconnect(&mut self) -> Result<(), MensagoError>;

    /// Returns true if connected
    fn is_connected(&self) -> bool;

    /// Waits for a ServerResponse from a connected Mensago server
    fn receive(&mut self) -> Result<ServerResponse, MensagoError>;

    /// Sends a ClientRequest to a server
    fn send(&mut self, msg: &ClientRequest) -> Result<(), MensagoError>;
}

/// The ServerConnection type is a low-level connection to a Mensago server that operates over
/// a TCP stream.
#[derive(Debug)]
pub struct ServerConnection {
    socket: Option<TcpStream>,
    buffer: [u8; BUFFER_SIZE],
}

impl ServerConnection {
    /// Creates a new ServerConnection object which is ready to connect to a server.
    pub fn new() -> ServerConnection {
        ServerConnection {
            socket: None,
            buffer: [0; BUFFER_SIZE],
        }
    }
}

impl MConn for ServerConnection {
    /// Connects to a Mensago server given the specified address and port. This call takes a string
    /// for the address so that an IP address or a domain may be used.
    fn connect(&mut self, address: &str, port: u16) -> Result<(), MensagoError> {
        if address.len() == 0 {
            return Err(MensagoError::ErrBadValue);
        }

        let mut sock = match TcpStream::connect(format!("{}:{}", address, port)) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };

        match sock.set_read_timeout(Some(*CONN_TIMEOUT)) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };

        // absorb the hello string for now
        let bytes_read = match sock.read(&mut self.buffer) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };

        let rawjson = match String::from_utf8(self.buffer[..bytes_read].to_vec()) {
            Ok(v) => v,
            Err(_) => return Err(MensagoError::ErrBadMessage),
        };
        let greeting: GreetingData = match serde_json::from_str(&rawjson.trim()) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "error parsing server greeting: {}",
                    e.to_string()
                )))
            }
        };

        if greeting.code != 200 {
            return Err(MensagoError::ErrProtocol(CmdStatus {
                code: greeting.code,
                description: greeting.status,
                info: String::new(),
            }));
        }

        self.socket = Some(sock);

        Ok(())
    }

    /// Returns true if connected to a server
    #[inline]
    fn is_connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Disconnects from the server by sending a QUIT command to the server and then closing the
    /// TCP session
    fn disconnect(&mut self) -> Result<(), MensagoError> {
        match self.socket {
            Some(_) => quit(self.socket.as_mut().unwrap()),
            None => Ok(()),
        }
    }

    fn receive(&mut self) -> Result<ServerResponse, MensagoError> {
        if self.socket.is_none() {
            return Err(MensagoError::ErrNotConnected);
        }
        ServerResponse::receive(self.socket.as_mut().unwrap())
    }

    fn send(&mut self, msg: &ClientRequest) -> Result<(), MensagoError> {
        if self.socket.is_none() {
            return Err(MensagoError::ErrNotConnected);
        }
        msg.send(self.socket.as_mut().unwrap())
    }
}
