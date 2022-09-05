use std::collections::HashMap;
use crate::base::*;
use crate::commands::servermsg::*;
use crate::conn::*;
use base85;
use eznacl::*;
use libkeycard::*;
use rand::thread_rng;
use rand::Rng;
use std::{thread, time::Duration};

/// Handles the process to upload a user entry to the server
pub fn addentry<V: VerifySignature>(conn: &mut ServerConnection, entry: &mut Entry, ovkey: &V, 
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
			("Base-Entry", entry.get_text()?.as_str()),
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
	entry.verify_signature("Organization-Signature", ovkey)?;
	
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
	thread::sleep(Duration::from_millis(10));
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
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	Ok(())
}

/// Replaces the specified device's key stored on the server. This is used specifically for
/// rotating device keys.
pub fn devkey(conn: &mut ServerConnection, devid: &RandomID, oldpair: &EncryptionPair,
newpair: &EncryptionPair) -> Result<(), MensagoError> {

	let req = ClientRequest::from(
		"DEVKEY", &vec![
			("Device-ID", devid.as_string()),
			("Old-Key", oldpair.get_public_str().as_str()),
			("New-Key", newpair.get_public_str().as_str()),
		]
	);
	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 100 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	if !resp.check_fields(&vec![("Challenge", true),("New-Challenge", true),
		]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	// Both challenges from the server are expected to be Base85-encoded random bytes that are
	// encrypted into a CryptoString. This means we decrypt the challenge and send the resulting
	// decrypted string back to the server as proof of device identity.
	
	let challstr = match CryptoString::from(&resp.data["Challenge"]) {
		Some(v) => v,
		None => {
			return Err(MensagoError::ErrBadValue)
		},
	};
	let rawbytes = match oldpair.decrypt(&challstr) {
		Ok(v) => v,
		Err(e) => {
			cancel(conn)?;
			return Err(MensagoError::EzNaclError(e));
		}
	};
	let oldresponse = String::from_utf8(rawbytes)?;

	let newchallstr = match CryptoString::from(&resp.data["New-Challenge"]) {
		Some(v) => v,
		None => {
			return Err(MensagoError::ErrBadValue)
		},
	};
	let newrawbytes = match newpair.decrypt(&newchallstr) {
		Ok(v) => v,
		Err(e) => {
			cancel(conn)?;
			return Err(MensagoError::EzNaclError(e));
		}
	};
	let newresponse = String::from_utf8(newrawbytes)?;

	let req = ClientRequest::from(
		"DEVKEY", &vec![
			("Device-ID", devid.as_string()),
			("Response", oldresponse.as_str()),
			("New-Response", newresponse.as_str()),
		]
	);
	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
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
	thread::sleep(Duration::from_millis(10));
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
	thread::sleep(Duration::from_millis(10));
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
pub fn iscurrent(conn: &mut ServerConnection, index: usize, wid: Option<&RandomID>)
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
	thread::sleep(Duration::from_millis(10));
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
	let mut rawchallenge = [0u8; 32];
    match thread_rng().try_fill(&mut rawchallenge[..]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("random number generator failure in login(): {}", e.to_string())
			))			
		}
	}
	let challenge = base85::encode(&rawchallenge);
	let echallenge = serverkey.encrypt(challenge.as_bytes())?;

	let req = ClientRequest::from(
		"LOGIN", &vec![
			("Workspace-ID", wid.to_string().as_str()),
			("Login-Type", "PLAIN"),
			("Challenge", echallenge.as_str()),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 100 {
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
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	Ok(())
}

/// Obtains keycard entries for the organization. This command is usually called to get a server's
/// entire keycard or to get updates to it. The start_index parameter refers to the Index field in 
/// the keycard entry. To obtain the entire keycard, use an index of 1. To obtain only the current
/// entry, use an index of 0. Specifying another value will result in the server returning all
/// entries from the specified index through the current one. If an index which is out of range is
/// specified, the server will return 404 NOT FOUND.
pub fn orgcard(conn: &mut ServerConnection, start_index: usize)
-> Result<Keycard, MensagoError> {

	let req = ClientRequest::from(
		"ORGCARD", &vec![("Start-Index", start_index.to_string().as_str())]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 104 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	if !resp.check_fields(&vec![
		("Total-Size", true),
		("Item-Count", true),
	]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	// Although we check to ensure that the server sticks to the spec for the fields in the
	// response, this client library is intended for desktops and mobile devices, so even a card
	// which is a few hundred KB is no big deal.
	
	// Send an empty TRANSFER request to confirm that we are ready to accept the card data
	conn.send(&ClientRequest::new("TRANSFER"))?;

	let resp = conn.receive()?;
	if resp.code != 104 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	if !resp.check_fields(&vec![
		("Total-Size", true),
		("Item-Count", true),
		("Card-Data", true),
	]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	let mut out = Keycard::new(EntryType::Organization);
	out.entries.append(&mut parse_entries(&resp.data["Card-Data"])?);

	Ok(out)
}

/// Allows a user to set a new password on their workspace given a registration code from an
/// administrator. The process for the user is meant to work exactly the same as setting up a
/// preregistered account.
pub fn passcode(conn: &mut ServerConnection, wid: &RandomID, reset_code: &str, pwhash: &str)
-> Result<(), MensagoError> {

	let req = ClientRequest::from(
		"PASSCODE", &vec![
			("Workspace-ID", wid.as_string()),
			("Reset-Code", reset_code),
			("Password-Hash", pwhash),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	Ok(())
}

/// Continues the login process by sending a password hash for the workspace. This function returns
/// a hashmap containing 4 String fields:
/// 
/// - devid - the RandomID that identifies the device to the server
/// - wid - the workspace ID of the account
/// - uid - the user ID of the account. This will be the same as the wid field for private accounts
/// - domain - the domain of the account
pub fn password(conn: &mut ServerConnection, pwhash: &ArgonHash)
-> Result<(), MensagoError> {

	let req = ClientRequest::from(
		"PASSWORD", &vec![
			("Password-Hash", pwhash.to_string().as_str()),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 100 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	Ok(())
}

/// Provisions a preregistered account on the server. Note that the uid, wid, and domain are all
/// optional. If none of them are specified, then the server generates an anonymous workspace with
/// the organization's default domain. This command requires administrator privileges.
pub fn preregister(conn: &mut ServerConnection, wid: Option<&RandomID>, uid: Option<&UserID>,
domain: Option<&Domain>) -> Result<HashMap<&'static str,String>, MensagoError> {

	let mut req = ClientRequest::new("PREREG");

	match wid {
		Some(w) => { req.data.insert(String::from("Workspace-ID"), w.to_string()); },
		None => (),
	}

	match uid {
		Some(u) => { req.data.insert(String::from("User-ID"), u.to_string()); },
		None => (),
	}

	match domain {
		Some(d) => { req.data.insert(String::from("Domain"), d.to_string()); },
		None => (),
	}

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	if !resp.check_fields(&vec![
			("Workspace-ID", true),
			("Reg-Code", true),
			("Domain", true),
		]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	let mut out = HashMap::<&'static str, String>::new();
	out.insert("domain", resp.data["Domain"].clone());
	out.insert("wid", resp.data["Workspace-ID"].clone());
	out.insert("regcode", resp.data["Reg-Code"].clone());

	Ok(out)
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
	thread::sleep(Duration::from_millis(10));
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

/// Creates an account on the server. The response received depends on a number of factors,
/// including the registration mode of the server.
pub fn register(conn: &mut ServerConnection, uid: Option<&UserID>, pwhash: &str, devid: &RandomID,
devicekey: &CryptoString) -> Result<HashMap<&'static str,String>, MensagoError> {

	let mut out = HashMap::<&'static str, String>::new();

	// This construct is a little strange, but it is to work around the minute possibility that
	// there is a WID collision, i.e. the WID generated by the client already exists on the server.
	// In such an event, it should try again. However, in the ridiculously small chance that the 
	// client keeps generating collisions, it should wait 3 seconds after 10 collisions to reduce 
	// server load.
	for tries in 0..10 {
		
		if tries > 0 {
			thread::sleep(Duration::from_secs(3))
		}
		
		// Technically, the active profile already has a WID, but it is not attached to a domain and
		// doesn't matter as a result. Rather than adding complexity, we just generate a new UUID
		// and always return the replacement value
		let testwid = RandomID::generate();
		let mut req = ClientRequest::from(
			"REGISTER", &vec![
				("Workspace-ID", testwid.to_string().as_str()),
				("Password-Hash", pwhash.to_string().as_str()),
				("Device-ID", devid.to_string().as_str()),
				("Device-Key", devicekey.to_string().as_str())
			]
		);

		match uid {
			Some(v) => {
				req.data.insert(String::from("User-ID"), v.to_string());
			},
			None => (),
		}
	
		conn.send(&req)?;

		let resp = conn.receive()?;

		
		match resp.code {
			101 | 201 => { // Success
				if !resp.check_fields(&vec![("Domain", true)]) {
					return Err(MensagoError::ErrSchemaFailure)
				}
				
				let domain = match resp.data.get("Domain") {
					Some(s) => {
						match Domain::from(s) {
							Some(d) => d,
							None => {
								return Err(MensagoError::ErrBadValue)
							}
						}
					},
					None => {
						return Err(MensagoError::ErrSchemaFailure)
					}
				};
				

				out.insert("devid", devid.to_string());
				out.insert("wid", testwid.to_string());
				out.insert("domain", domain.to_string());
				if uid.is_some() {
					out.insert("uid", uid.unwrap().to_string());
				}
				break;
			},
			408 => { // UID or WID exists
				if !resp.check_fields(&vec![
					("Field", true),
				]) {
					return Err(MensagoError::ErrSchemaFailure)
				}

				match resp.data["Field"].as_str() {
					"User-ID" => {
						return Err(MensagoError::ErrExists)
					},
					"Workspace-ID" => {
						// Continue through to next iteration. This case will happen extremely
						// rarely, if ever -- the randomly-generated workspace ID exists on the
						// server.
					},
					_ => {
						return Err(MensagoError::ErrServerException(
							String::from("Bad Field value in 408 error code from server")
						))
					},
				}

			},
			_ => { // Some other error
				return Err(MensagoError::ErrProtocol(resp.as_status()))
			},
		} // end match on response code
	} // end for loop
	
	Ok(out)
}

/// Unlike setpassword(), this is an administrator command to reset the password for a user account.
/// The `reset_code` and `expires` parameters are completely optional and exist only to give the
/// administrator the option of choosing the reset code and expiration time. If omitted, the server
/// will generate a secure reset code that will expire in the default period of time configured.
/// 
/// Mensago password resets are very different from other platforms in that the process is designed
/// such that at no time does the administrator know the user's password.
pub fn reset_password(conn: &mut ServerConnection, wid: &RandomID, reset_code: Option<&str>,
expires: Option<&Timestamp>) -> Result<HashMap<&'static str,String>, MensagoError> {

	let mut req = ClientRequest::from(
		"RESETPASSWORD", &vec![("Workspace-ID", wid.to_string().as_str())]
	);

	match reset_code {
		Some(r) => { req.data.insert(String::from("Reset-Code"), String::from(r)); },
		None => (),
	}
	
	match expires {
		Some(x) => { req.data.insert(String::from("Expires"), x.to_string()); },
		None => (),
	}

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	let mut out = HashMap::<&'static str, String>::new();
	out.insert("expires", resp.data["Expires"].clone());
	out.insert("resetcode", resp.data["Reset-Code"].clone());

	Ok(out)
}

/// Allows a user to change their workspace's password. For administrator-assisted password resets,
/// use resetpassword().
pub fn setpassword(conn: &mut ServerConnection, pwhash: &ArgonHash, newpwhash: &ArgonHash)
-> Result<(), MensagoError> {

	let req = ClientRequest::from(
		"SETPASSWORD", &vec![
			("Password-Hash", pwhash.to_string().as_str()),
			("NewPassword-Hash", newpwhash.to_string().as_str()),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	Ok(())
}

/// Sets the activity status of the workspace specified. Requires admin privileges. Currently the
/// status may be 'active', 'disabled', or 'approved', the last of which is used only for moderated
/// registration.
pub fn setstatus(conn: &mut ServerConnection, wid: &RandomID, status: &str)
-> Result<(), MensagoError> {

	match status {
		"active" | "disabled" | "approved" => (),
		_ => {
			return Err(MensagoError::ErrBadValue)
		},
	}

	let req = ClientRequest::from(
		"SETSTATUS", &vec![
			("Workspace-ID", wid.to_string().as_str()),
			("Status", status),
		]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	Ok(())
}

/// Deletes the user's account from the connected server. This can be the user's identity account,
/// but it could also be a membership on a shared workspace when that feature is implemented. In
/// the case of servers using private or moderated registration, this command will return either an
/// error or a Pending status.
pub fn unregister(conn: &mut ServerConnection, pwhash: &ArgonHash)
-> Result<CmdStatus, MensagoError> {

	let req = ClientRequest::from(
		"UNREGISTER", &vec![("Password-Hash", pwhash.to_string().as_str())]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	thread::sleep(Duration::from_millis(10));
	if resp.code != 200 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}
	
	// This particular command is very simple: make a request, because the server will return one of
	// of three possible types of responses: success, pending (for private/moderated 
	// registration modes), or an error. In all of those cases there isn't anything else to do.
	Ok(resp.as_status())
}

/// Obtains keycard entries for a user. This command is usually called to get a user's entire
/// keycard or to get updates to it. The start_index parameter refers to the Index field in 
/// the keycard entry. To obtain the entire keycard, use an index of 1. To obtain only the current
/// entry, use an index of 0. Specifying another value will result in the server returning all
/// entries from the specified index through the current one. If an index which is out of range is
/// specified, the server will return 404 NOT FOUND.
pub fn usercard(conn: &mut ServerConnection, start_index: usize)
-> Result<Keycard, MensagoError> {

	let req = ClientRequest::from(
		"USERCARD", &vec![("Start-Index", start_index.to_string().as_str())]
	);

	conn.send(&req)?;

	let resp = conn.receive()?;
	if resp.code != 104 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	if !resp.check_fields(&vec![
		("Total-Size", true),
		("Item-Count", true),
	]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	// Although we check to ensure that the server sticks to the spec for the fields in the
	// response, this client library is intended for desktops and mobile devices, so even a card
	// which is a few hundred KB is no big deal.
	
	// Send an empty TRANSFER request to confirm that we are ready to accept the card data
	conn.send(&ClientRequest::new("TRANSFER"))?;

	let resp = conn.receive()?;
	if resp.code != 104 {
		return Err(MensagoError::ErrProtocol(resp.as_status()))
	}

	if !resp.check_fields(&vec![
		("Total-Size", true),
		("Item-Count", true),
		("Card-Data", true),
	]) {
		return Err(MensagoError::ErrSchemaFailure)
	}

	let mut out = Keycard::new(EntryType::User);
	out.entries.append(&mut parse_entries(&resp.data["Card-Data"])?);

	Ok(out)
}
