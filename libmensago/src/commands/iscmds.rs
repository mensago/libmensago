use std::collections::HashMap;
use crate::base::*;
use crate::commands::servermsg::*;
use crate::conn::*;
use base85;
use eznacl::*;
use libkeycard::*;
use rand::thread_rng;
use rand::Rng;

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
pub fn login<E: Encryptor>(conn: &mut ServerConnection, wid: &RandomID, serverkey: &E)
-> Result<(), MensagoError> {

	// We have a challenge for the server to ensure that we're connecting to the server we *think*
	// we are.
	let mut challenge = [0u8; 32];
    match thread_rng().try_fill(&mut challenge[..]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("random number generator failure in login(): {}", e.to_string())
			))			
		}
	}
	let echallenge = serverkey.encrypt(&challenge[..])?;

	let req = ClientRequest::from(
		"LOGIN", &vec![
			("Workspace-ID", wid.to_string().as_str()),
			("Login-Type", "PLAIN"),
			("Challenge", echallenge.as_str()),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 201 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![("Response", true),]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	Ok(())
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
devid: &RandomID, devpubkey: &CryptoString) -> Result<HashMap<&'static str,String>, MensagoError> {

	let mut req = ClientRequest::from(
		"REGCODE", &vec![
			("Reg-Code", code),
			("Password-Hash", &pwhash.to_string()),
			("Device-ID", &devid.to_string()),
			("Device-Key", &devpubkey.to_string()),
			("Domain", &address.domain.to_string()),
		]
	);

	if address.uid.get_type() == IDType::WorkspaceID {
		req.data.insert(String::from("Workspace-ID"), address.uid.to_string());
	} else {
		req.data.insert(String::from("User-ID"), address.uid.to_string());
	}

	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 201 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![
			("Workspace-ID", true),
			("User-ID", true),
			("Domain", true),
		]) {
		return Err(MensagoError::ErrSchemaFailure)
	}
	
	let mut out = HashMap::<&'static str,String>::new();
	out.insert("devid", devid.to_string());
	out.insert("wid", resp.data["Workspace-ID"].clone());
	out.insert("uid", resp.data["User-ID"].clone());
	out.insert("domain", resp.data["Domain"].clone());

	Ok(out)
}
