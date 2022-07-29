

#[cfg(test)] 
mod tests {
	use libkeycard::*;
	use libmensago::*;
	use crate::common::*;
	use std::path::PathBuf;

	#[test]
	fn test_getwid() -> Result<(), MensagoError> {
		let testname = "test_getwid";

		let mut config = load_server_config(true)?;
		let mut db = match setup_test(&config) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: setup_test error: {}", testname, e.to_string())
				))
			}
		};
		let dbdata = match init_server(&mut db) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: init_server error: {}", testname, e.to_string())
				))
			}
		};
		let profile_folder = match setup_profile_base(testname) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: setup_profile_base error: {}", testname, e.to_string())
				))
			}
		};
		let pwhash = match setup_profile(&profile_folder, &mut config, &ADMIN_PROFILE_DATA) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: setup_profile error: {}", testname, e.to_string())
				))
			}
		};

		let mut profman = ProfileManager::new(&PathBuf::from(&profile_folder));
		match profman.load_profiles(Some(&PathBuf::from(&profile_folder))) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: load_profiles error: {}", testname, e.to_string())
				))
			}
		};

		let mut conn = ServerConnection::new();
		let port = config["network"]["port"].as_integer().unwrap();
		match conn.connect(config["network"]["listen_ip"].as_str().unwrap(), &port.to_string()) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error connecting to server: {}", testname, e.to_string())
				))
			}
		}
		
		match regcode_user(&mut conn, &mut profman, &dbdata, &ADMIN_PROFILE_DATA,
			&dbdata["admin_regcode"], &pwhash) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: regcode_user error: {}", testname, e.to_string())
				))
			}
		}

		let wid = match getwid(&mut conn, &UserID::from("admin").unwrap(),
			Domain::from("example.com").as_ref()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: getwid failed: {}", testname, e.to_string())
				))
			}
		};

		let admin_wid = RandomID::from(&dbdata["admin_wid"]).unwrap();
		if wid != admin_wid {
			return Err(MensagoError::ErrProgramException(
				format!("{}: wid mismatch: wanted {}, got {}", testname, wid.to_string(),
					admin_wid.to_string())
			))
		}

		conn.disconnect()?;

		Ok(())
	}

}