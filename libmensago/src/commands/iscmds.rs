use crate::base::*;
use crate::commands::servermsg::*;
use crate::conn::*;
use libkeycard::*;

pub fn getwid(conn: &mut ServerConnection, uid: &UserID, domain: Option<&Domain>)
-> Result<RandomID, MensagoError> {

	let mut req = ClientRequest::from(
		"GETWID", &vec![
			("User-ID", uid.as_string()),
		]
	);

	if domain.is_some() {
		req.data.insert(String::from("Domain"), String::from(domain.unwrap().as_string()));
	}
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![("Workspace-ID", true)]) {
		return Err(MensagoError::ErrSchemaFailure)
	}
	
	match RandomID::from(resp.data.get("Workspace-ID").unwrap()) {
		Some(v) => Ok(v),
		None => { return Err(MensagoError::ErrBadValue) }
	}
}

pub fn iscurrent(conn: &mut ServerConnection, index: usize, wid: Option<RandomID>)
-> Result<bool, MensagoError> {

	let mut req = ClientRequest::from(
		"ISCURRENT", &vec![
			("Index", index.to_string().as_str())
		]
	);

	if wid.is_some() {
		req.data.insert(String::from("Workspace-ID"), String::from(wid.unwrap().as_string()));
	}
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![("Is-Current", true)]) {
		return Err(MensagoError::ErrSchemaFailure)
	}
	
	Ok(resp.data.get("Is-Current").unwrap() == "YES")
}
