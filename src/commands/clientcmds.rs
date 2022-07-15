use crate::base::*;
use crate::commands::servermsg::*;
use std::net::TcpStream;

pub fn quit(conn: &mut TcpStream) -> Result<(), MensagoError> {

	let quitreq = ClientRequest::new("QUIT");
	quitreq.send(conn)
}
