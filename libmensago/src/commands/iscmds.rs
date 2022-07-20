use crate::base::*;
use crate::commands::servermsg::*;
use crate::conn::*;
use eznacl::*;
use libkeycard::*;

/// Completes the login process by submitting the device ID and responding to the server's device
/// challenge.
pub fn device(conn: &mut ServerConnection, devid: &RandomID, devpair: &EncryptionPair)
-> Result<(), MensagoError> {

	// TODO: implement iscmds::device()
	return Err(MensagoError::ErrUnimplemented)
}

/// Looks up a workspace ID based on the specified user ID and optional domain. If the domain is
/// not specified, the organization's domain is used.
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

/// Finds out if an entry index is current. If workspace ID is omitted, this command checks the
/// index for the organization's keycard.
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

/// Starts the login process by submitting the desired workspace ID.
pub fn login(conn: &mut ServerConnection, wid: &RandomID, serverkey: &CryptoString)
-> Result<(), MensagoError> {

	// TODO: implement iscmds::login()
	return Err(MensagoError::ErrUnimplemented)
}

/// Continues the login process by sending a password hash for the workspace
pub fn password(conn: &mut ServerConnection, pwhash: &ArgonHash)
-> Result<(), MensagoError> {

	// TODO: implement iscmds::password()
	return Err(MensagoError::ErrUnimplemented)
}

/// Finishes the registration of a workspace. The address may be a regular Mensago address or it 
/// can be a workspace address.
pub fn regcode(conn: &mut ServerConnection, address: &MAddress, code: &str, pwhash: &ArgonHash, 
devid: &RandomID, devpubkey: &CryptoString) -> Result<(), MensagoError> {

	// TODO: implement iscmds::regcode()
	return Err(MensagoError::ErrUnimplemented)
}
