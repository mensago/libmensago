use crate::base::*;
use crate::commands::servermsg::*;
use libkeycard::*;
use std::net::TcpStream;

pub fn getwid(conn: &mut TcpStream, uid: &UserID, domain: Option<&Domain>)
-> Result<RandomID, MensagoError> {

	let req = ClientRequest::from(
		"GETWID", vec![
			("User-ID", uid.as_string()),
		]
	);

	if domain.is_some() {
		req.data.insert(String::from("Domain"), String::from(domain.unwrap().as_string()));
	}

	let resp = ServerResponse::receive(conn)?;

	// TODO: finish implementing getwid()
	
	Err(MensagoError::ErrUnimplemented)
}