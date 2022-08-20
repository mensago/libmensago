

#[cfg(test)] 
mod tests {
	use eznacl::*;
	use libkeycard::*;
	use libmensago::*;
	use crate::common::*;
	use std::path::PathBuf;
	
	// addentry() is tested by common.rs::test_regcode_user()
	
	// device() is tested by common.rs::test_regcode_user()

	#[test]
	fn test_devkey() -> Result<(), MensagoError> {
		let testname = "test_devkey";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, _, _, mut conn, admin_regdata) = full_test_setup(testname)?;

		let oldpair = EncryptionPair::from_strings(ADMIN_PROFILE_DATA["device.public"].as_str(),
			ADMIN_PROFILE_DATA["device.private"].as_str())?;
		let newpair = EncryptionPair::generate("CURVE25519").unwrap();
		let devid = RandomID::from(admin_regdata["devid"].as_str()).unwrap();

		match devkey(&mut conn, &devid, &oldpair, &newpair) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: devkey error: {}", testname, e.to_string())
				))
			}
		}

		conn.disconnect()?;

		Ok(())
	}

	#[test]
	fn test_getwid() -> Result<(), MensagoError> {
		let testname = "test_getwid";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, dbdata, _, _, _, mut conn, _) = full_test_setup(testname)?;

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

	// login() is tested by common.rs::test_regcode_user()

	#[test]
	fn test_orgcard() -> Result<(), MensagoError> {
		let testname = "test_orgcard";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, _, _, mut conn, _) = full_test_setup(testname)?;

		let card = match orgcard(&mut conn, 1) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: full card request failed: {}", testname, e.to_string())
				))
			}
		};
		if card.entries.len() != 2 {
			return Err(MensagoError::ErrProgramException(
				format!("{}: entry count mismatch: wanted 2, got {}", testname, card.entries.len())
			))
		}


		conn.disconnect()?;

		Ok(())
	}

	#[test]
	fn test_preregister_regcode() -> Result<(), MensagoError> {
		let testname = "test_preregister";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, pwhash, _, mut conn, _) = full_test_setup(testname)?;
	
		let userwid = RandomID::from(&USER1_PROFILE_DATA["wid"]);
		let useruid = UserID::from(&USER1_PROFILE_DATA["uid"]);
		let userdomain = Domain::from(&USER1_PROFILE_DATA["domain"]);
		let userregdata = match preregister(&mut conn, userwid.as_ref(), useruid.as_ref(),
			userdomain.as_ref()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("preregister() failed in {}: {}", testname, e.to_string())
				))
			},
		};

		let devid = RandomID::from(&USER1_PROFILE_DATA["devid"]).unwrap();
		match regcode(&mut conn, MAddress::from(&USER1_PROFILE_DATA["address"]).as_ref().unwrap(),
			&userregdata["regcode"], &pwhash, &devid,
			&CryptoString::from(&USER1_PROFILE_DATA["device.public"]).unwrap()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("use regcode failed in regcode_user: {}", e.to_string())
				))
			},
		};

		conn.disconnect()?;

		Ok(())
	}

	#[test]
	fn test_register() -> Result<(), MensagoError> {
		let testname = "test_register";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, pwhash, _, mut conn, _) = full_test_setup(testname)?;
		
		let devid = RandomID::generate();
		let devpair = EncryptionPair::generate("CURVE25519")?;
		match register(&mut conn, UserID::from("csimons").as_ref(), &pwhash.to_string(), &devid,
			&devpair.get_public_key()) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: register error: {}", testname, e.to_string())
				))
			}
		}
		conn.disconnect()?;

		Ok(())
	}

	#[test]
	fn test_reset_password() -> Result<(), MensagoError> {
		let testname = "test_reset_password";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, _, _, mut conn, _) = full_test_setup(testname)?;

		// Preregister the regular user
		let userwid = RandomID::from(&USER1_PROFILE_DATA["wid"]);
		let useruid = UserID::from(&USER1_PROFILE_DATA["uid"]);
		let userdomain = Domain::from(&USER1_PROFILE_DATA["domain"]);
		// let userregdata = match preregister(&mut conn, userwid.as_ref(), useruid.as_ref(),
		match preregister(&mut conn, userwid.as_ref(), useruid.as_ref(),
			userdomain.as_ref()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("preregister() failed in {}: {}", testname, e.to_string())
				))
			},
		};
		conn.disconnect()?;

		// Log in as the user and set up the profile

		// TODO: finish test_reset_password() once client type is implemented

		Ok(())
	}

	#[test]
	fn test_setpassword() -> Result<(), MensagoError> {
		let testname = "test_setpassword";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, pwhash, _, mut conn, _) = full_test_setup(testname)?;

		let badpassword = ArgonHash::from_hashstr(USER1_PROFILE_DATA["passhash"].as_str());
		let newpassword = ArgonHash::from_hashstr("$argon2id$v=19$m=65536,t=2,p=1$CXh8Mzm\
		TlJNrNddm2RqWAg$874zZGneIsc1QyUJcW7O9SRrbgkF0gTKo4xdbJOiZU0");
		match setpassword(&mut conn, &badpassword, &newpassword) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: setpassword allowed a bad password", testname)
				))
			},
			Err(_) => (),
		}

		match setpassword(&mut conn, &pwhash, &newpassword) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: setpassword() error: {}", testname, e.to_string())
				))
			}
		}
		
		conn.disconnect()?;

		Ok(())
	}

	#[test]
	fn test_usercard() -> Result<(), MensagoError> {
		let testname = "test_usercard";

		// This is an... involved... test. :( First, all the basic server and admin setup

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
		
		// match regcode_user(&mut conn, &mut profman, &dbdata, &ADMIN_PROFILE_DATA,
		// 	&dbdata["admin_regcode"], &pwhash) {
		// 	Ok(_) => (),
		// 	Err(e) => {
		// 		return Err(MensagoError::ErrProgramException(
		// 			format!("{}: regcode_user error: {}", testname, e.to_string())
		// 		))
		// 	}
		// };

		// // Now that the admin has been registered and is logged in, prereg a regular user
		// let user_regdata = match preregister(&mut conn, 
		// 	Some(&RandomID::from(&USER1_PROFILE_DATA["wid"]).unwrap()),
		// 	Some(&UserID::from(&USER1_PROFILE_DATA["uid"]).unwrap()),
		// 	Some(&Domain::from(&USER1_PROFILE_DATA["domain"]).unwrap())) {
		// 	Ok(v) => (v),
		// 	Err(e) => {
		// 		return Err(MensagoError::ErrProgramException(
		// 			format!("{}: error preregistering test user: {}", testname, e.to_string())
		// 		))
		// 	}
		// };
		
		conn.disconnect()?;

		// TODO: finish test_usercard() once the client front is started

		// Log in as the test user and set up a complete profile

		Ok(())
	}
}