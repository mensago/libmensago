#[cfg(test)] 
mod tests {
	use libmensago::*;
	use crate::common::*;
	
	#[test]
	fn test_register() -> Result<(), MensagoError> {
		let testname = "test_register";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, dbdata, _, _, _, mut conn, _) = full_test_setup(testname)?;

		// TODO: finish test_register()

		conn.disconnect()?;


		Ok(())
	}
}