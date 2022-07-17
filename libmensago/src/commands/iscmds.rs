use crate::base::*;
use crate::commands::servermsg::*;
use libkeycard::*;
use std::net::TcpStream;

pub fn getwid(conn: &mut TcpStream, uid: &UserID, domain: Option<&Domain>)
-> Result<RandomID, MensagoError> {

	let mut req = ClientRequest::from(
		"GETWID", &vec![
			("User-ID", uid.as_string()),
		]
	);

	if domain.is_some() {
		req.data.insert(String::from("Domain"), String::from(domain.unwrap().as_string()));
	}
	req.send(conn)?;

	let resp = ServerResponse::receive(conn)?;
	if resp.status.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.status))
	}
	
	if !resp.check_fields(&vec![("Workspace-ID", true)]) {
		return Err(MensagoError::ErrSchemaFailure)
	}
	
	match RandomID::from(resp.data.get("Workspace-ID").unwrap()) {
		Some(v) => Ok(v),
		None => { return Err(MensagoError::ErrBadValue) }
	}
}

pub fn iscurrent(conn: &mut TcpStream, index: usize, wid: Option<RandomID>)
-> Result<bool, MensagoError> {

	let mut req = ClientRequest::from(
		"ISCURRENT", &vec![
			("Index", index.to_string().as_str())
		]
	);

	if wid.is_some() {
		req.data.insert(String::from("Workspace-ID"), String::from(wid.unwrap().as_string()));
	}
	req.send(conn)?;

	let resp = ServerResponse::receive(conn)?;
	if resp.status.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.status))
	}
	
	if !resp.check_fields(&vec![("Is-Current", true)]) {
		return Err(MensagoError::ErrSchemaFailure)
	}
	
	Ok(resp.data.get("Is-Current").unwrap() == "YES")
}
