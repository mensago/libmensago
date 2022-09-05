
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

		let mut profile_path = PathBuf::from(profile_folder);
		profile_path.push("primary");

		let mut resolver = match KCResolver::new(&profile_path) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: failed to create resolver: {}", testname, e.to_string())
				))
			}
		};

		let mut dh = FakeDNSHandler::new();
		let admin_addr = match resolver.resolve_address(
			&MAddress::from("admin/example.com").unwrap(), &mut dh) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: failed to resolve admin address: {}", testname, e.to_string())
				))
			}
		};

		if admin_addr != RandomID::from("ae406c5e-2673-4d3e-af20-91325d9623ca").unwrap() {
			return Err(MensagoError::ErrProgramException(
				format!("{}: admin address mismatch: {}", testname, admin_addr.to_string())
			))
		}

		let orgcard = match resolver.get_card("example.com", &mut dh, false) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: failed to get org card: {}", testname, e.to_string())
				))
			}
		};

		// TODO: finish implementing test_kcresolver()

		Ok(())
	}
}
