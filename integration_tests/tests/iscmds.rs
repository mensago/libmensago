

#[cfg(test)] 
mod tests {
	use libkeycard::*;
	use libmensago::*;
	use crate::common::*;

	#[test]
	fn test_getwid() -> Result<(), MensagoError> {
		let testname = "test_getwid";

		let mut config = load_server_config(true)?;
		let _ = setup_test(&config)?;
		let profile_folder = setup_profile_base("test_getwid")?;
		setup_profile(&profile_folder, &mut config, &ADMIN_PROFILE_DATA)?;

		let mut conn = ServerConnection::new();
		conn.connect("localhost", "2001")?;

		// TODO: call regcode here

		let wid = match getwid(&mut conn, &UserID::from("admin").unwrap(),
			Domain::from("example.com").as_ref()) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: getwid failed: {}", testname, e.to_string())
				))
			}
		};

		// TODO: test wid against admin wid
		Ok(())
	}

}