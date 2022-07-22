use std::collections::HashMap;
use crate::base::*;
use crate::commands::servermsg::*;
use crate::conn::*;
use eznacl::*;
use libkeycard::*;
use rand::thread_rng;
use rand::Rng;

/// Handles the process to upload a user entry to the server
pub fn addentry<V: VerifySignature>(conn: &mut ServerConnection, entry: &mut Entry, ovkey: V, 
spair: &SigningPair) -> Result<(), MensagoError> {

	// NOTE: adding an entry to the keycard database must be handled carefully -- security and
	// integrity of the keycard chain tree depends on all t's being crossed and all i's being
	// dotted. Don't make changes to this unless you fully understand the process here and have
	// also double-checked your work.

	// Before we start, make sure that the data in the entry is compliant
	entry.is_data_compliant()?;

	// The first round trip to the server provides us with the organization's signature, the hash
	// of the previous entry in the chain tree, and the server's hash of the data we sent. We can't
	// just use the hash of the previous entry in the keycard because the root entry of a user
	// keycard is attached to the chain tree at the latest entry in the organization's keycard. We
	// send the data to the server for the hashes and signature because the server doesn't trust
	// clients any more than the clients trust the server. It provides the hashes and signature, but
	// we verify everything that it gives us.
	let req = ClientRequest::from(
		"ADDENTRY", &vec![
			("Base-Entry", entry.get_full_text("")?.as_str()),
		]
	);
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 100 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![
			("Organization-Signature", true),
			("Hash", true),
			("Previous-Hash", true),
		]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	// Verify the organization's signature and hashes against the data stored locally to ensure that
	// the server didn't change our entry and sign or hash the modified version
	let org_sig = match CryptoString::from(&resp.data["Organization-Signature"]) {
		Some(v) => v,
		None => {
			return Err(MensagoError::ErrServerException(
				format!("Server exception: bad signature returned ({})", 
					&resp.data["Organization-Signature"])
			))
		}
	};
	entry.add_authstr("Organization-Signature", &org_sig)?;
	entry.verify_signature("Organization-Signature", &ovkey)?;
	
	let prev_hash = match CryptoString::from(&resp.data["Previous-Hash"]) {
		Some(v) => v,
		None => {
			return Err(MensagoError::ErrServerException(
				format!("Server exception: bad previous hash returned ({})", 
					&resp.data["Previous-Hash"])
			))
		}
	};
	entry.add_authstr("Previous-Hash", &prev_hash)?;
	
	let hash = match CryptoString::from(&resp.data["Hash"]) {
		Some(v) => v,
		None => {
			return Err(MensagoError::ErrServerException(
				format!("Server exception: bad entry hash returned ({})", 
					&resp.data["Hash"])
			))
		}
	};
	entry.add_authstr("Hash", &hash)?;
	entry.verify_hash()?;

	// Having come this far:
	// 1) The raw entry data has been verified by us
	// 2) The raw entry data has theoretically been verified by the server, digitally signed with
	//    the organization's primary signing key, linked into the keycard chain tree, and hashed.
	// 3) We have also verified that the signature and hash match the data we have locally so that
	//    the server can't have modified our data before signing and hashing

	// Next steps: sign with our key and upload to the server where it verifies everything again
	// before officially adding it to the keycard chain tree.

	entry.sign("User-Signature", &spair)?;
	entry.is_compliant()?;

	let req = ClientRequest::from(
		"ADDENTRY", &vec![
			("User-Signature", entry.get_authstr("User-Signature")?.as_str()),
		]
	);
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	Ok(())
}

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
