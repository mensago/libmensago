

#[cfg(test)] 
mod tests {
	use libmensago::*;
	use crate::common::*;

	#[test]
	fn test_getwid() -> Result<(), MensagoError> {

		let mut config = load_server_config(true)?;
		let db = setup_test(&config);
		let profile_folder = setup_profile_base("test_getwid")?;
		setup_profile(&profile_folder, &mut config, &ADMIN_PROFILE_DATA)?;

		// TODO: connect to server
		// TODO: issue and test getwid()
		Ok(())
	}

}