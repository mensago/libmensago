#[cfg(test)] 
mod tests {
	use libkeycard::*;
	use libmensago::*;
	use crate::common::*;
	
	#[test]
	fn test_register() -> Result<(), MensagoError> {
		let testname = "test_register";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;

		conn.disconnect()?;

		let mut client = match Client::new(&profile_folder.to_string()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error initializing client: {}", testname, e.to_string())
				))
			}
		};
		client.enable_test_mode(true);

		match client.get_profile_manager().create_profile("user") {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error creating test user profile: {}", testname, e.to_string())
				))
			}
		}

		match client.get_profile_manager().activate_profile("user") {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error activating test user profile: {}", testname, e.to_string())
				))
			}
		}

		let example_com = Domain::from("example.com").unwrap();
		match client.connect(&example_com) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error connecting to example.com: {}", testname, e.to_string())
				))
			}
		}

		match client.register(&example_com, "MyS3cretPassw*rd", 
			Some(&UserID::from("csimons").unwrap())) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error registering test user: {}", testname, e.to_string())
				))
			}
		};

		client.disconnect()?;

		Ok(())
	}
}