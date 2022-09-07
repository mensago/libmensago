
#[cfg(test)] 
mod tests {
	use libkeycard::*;
	use libmensago::*;
	use crate::common::*;
	
	#[test]
	fn test_kcresolver() -> Result<(), MensagoError> {
		let testname = "test_kcresolver";

		// The list of full data is as follows:
		// let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) = 
		// 	full_test_setup(testname)?;
		let (_, _, _, _, _, profman, mut conn, _) = full_test_setup(testname)?;
		conn.disconnect()?;

		let profile = profman.get_active_profile().unwrap();
		let mut resolver = match KCResolver::new(&profile) {
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

		// Just do a basic check that we got what we expected
		if orgcard.entries.len() != 2 {
			return Err(MensagoError::ErrProgramException(
				format!("{}: wrong org card entry count: wanted 2, got {}", testname,
					orgcard.entries.len())
			))
		}

		let usercard = match resolver.get_card("admin/example.com", &mut dh, false) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: failed to get user card: {}", testname, e.to_string())
				))
			}
		};

		// Just do a basic check that we got what we expected
		if usercard.entries.len() != 1 {
			return Err(MensagoError::ErrProgramException(
				format!("{}: wrong user card entry count: wanted 1, got {}", testname,
					orgcard.entries.len())
			))
		}

		Ok(())
	}
}
