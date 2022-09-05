
#[cfg(test)] 
mod tests {
	use libkeycard::*;
	use libmensago::*;
	use std::path::PathBuf;
	use crate::common::*;
	
	#[test]
	fn test_kcresolver() -> Result<(), MensagoError> {
		let testname = "test_kcresolver";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;
		conn.disconnect()?;

		let profile_path = PathBuf::from(profile_folder);
		let mut resolver = match KCResolver::new(&profile_path) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: failed to create resolver: {}", testname, e.to_string())
				))
			}
		};

		Ok(())
	}
}
