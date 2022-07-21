use std::collections::HashMap;
use std::os::raw;
use crate::base::*;
use crate::commands::servermsg::*;
use crate::conn::*;
use eznacl::*;
use libkeycard::*;
use rand::thread_rng;
use rand::Rng;

/// Returns the session to a state where it is ready for the next command
pub fn cancel(conn: &mut ServerConnection) -> Result<(), MensagoError> {

	let req = ClientRequest::new("CANCEL");
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	Ok(())
}

/// Completes the login process by submitting the device ID and responding to the server's device
/// challenge. The call returns true if the user has admin privileges or false if not.
pub fn device(conn: &mut ServerConnection, devid: &RandomID, devpair: &EncryptionPair)
-> Result<bool, MensagoError> {

	let req = ClientRequest::from(
		"DEVICE", &vec![
			("Device-ID", devid.as_string()),
			("Device-Key", devpair.get_public_str().as_str()),
		]
	);
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 100 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![("Challenge", true)]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	// The challenge from the server is expected to be Base85-encoded random bytes that are
	// encrypted into a CryptoString. This means we decrypt the challenge and send the resulting
	// decrypted string back to the server as proof of device identity.
	let keystr = match CryptoString::from(resp.data.get("Challenge").unwrap()) {
		Some(v) => v,
		None => {
			return Err(MensagoError::ErrBadValue)
		},
	};
	let rawbytes = match devpair.decrypt(&keystr) {
		Ok(v) => v,
		Err(e) => {
			cancel(conn)?;
			return Err(MensagoError::EzNaclError(e));
		}
	};
	let dchallenge = String::from_utf8(rawbytes)?;

	let req = ClientRequest::from(
		"DEVICE", &vec![
			("Device-ID", devid.as_string()),
			("Device-Key", devpair.get_public_str().as_str()),
			("Response", dchallenge.as_str()),
		]
	);
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![("Is-Admin", true)]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	Ok(resp.data["Is-Admin"] == "True")
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

/// Logs the current user out without disconnecting
pub fn logout(conn: &mut ServerConnection) -> Result<(), MensagoError> {

	let req = ClientRequest::new("QUIT");
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	Ok(())
}

/// Continues the login process by sending a password hash for the workspace
pub fn password(conn: &mut ServerConnection, pwhash: &ArgonHash)
-> Result<(), MensagoError> {

	let req = ClientRequest::from(
		"PASSWORD", &vec![
			("Password-Hash", pwhash.to_string().as_str()),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 100 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	Ok(())
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

/// Sets the activity status of the workspace specified. Requires admin privileges.
pub fn setstatus(conn: &mut ServerConnection, wid: &RandomID, status: &str)
-> Result<(), MensagoError> {

	match status {
		"active" | "disabled" | "approved" => (),
		_ => {
			return Err(MensagoError::ErrBadValue)
		},
	}

	let mut req = ClientRequest::from(
		"SETSTATUS", &vec![
			("Workspace-ID", wid.to_string().as_str()),
			("Status", status),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	Ok(())
}
