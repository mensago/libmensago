
#[cfg(test)] 
mod tests {
	use crate::common::*;
	use libkeycard::*;
	use libmensago::*;
	use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
	
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

	#[test]
	fn test_lookup_a() -> Result<(), MensagoError> {
		let testname = "test_lookup_a";

		let example_com = IpAddr::V4(Ipv4Addr::new(93,184,216,34));
		let mut real_handler = DNSHandler::new_default().unwrap();
		let returned_ip = match real_handler.lookup_a(&Domain::from("example.com").unwrap()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error looking up address: {}", testname, e.to_string())
				))
			}
		};
		assert_eq!(returned_ip, example_com);

		let loopback = IpAddr::V4(Ipv4Addr::new(127,0,0,1));
		let mut fake_handler = FakeDNSHandler::new();
		let returned_ip = match fake_handler.lookup_a(&Domain::from("example.com").unwrap()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error faking address lookup: {}", testname, e.to_string())
				))
			}
		};
		assert_eq!(returned_ip, loopback);

		Ok(())
	}

	#[test]
	fn test_lookup_aaaa() -> Result<(), MensagoError> {
		let testname = "test_lookup_aaaa";

		let example_com = IpAddr::V6(Ipv6Addr::new(0x2606,0x2800,0x220,1,0x248,0x1893,0x25c8,0x1946));
		let mut real_handler = DNSHandler::new_default().unwrap();
		let returned_ip = match real_handler.lookup_aaaa(&Domain::from("example.com").unwrap()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error looking up address: {}", testname, e.to_string())
				))
			}
		};
		assert_eq!(returned_ip, example_com);

		let loopback = IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,1));
		let mut fake_handler = FakeDNSHandler::new();
		let returned_ip = match fake_handler.lookup_aaaa(&Domain::from("example.com").unwrap()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error faking address lookup: {}", testname, e.to_string())
				))
			}
		};
		assert_eq!(returned_ip, loopback);

		Ok(())
	}

	#[test]
	fn test_lookup_srv() -> Result<(), MensagoError> {
		let testname = "test_lookup_srv";

		let mut real_handler = DNSHandler::new_default().unwrap();

		// mensago.net is currently used for testing and development purposes, so we can count
		// on this returning specific values
		match real_handler.lookup_srv(
			&String::from("_mensago._tcp.mensago.net.")) {
			
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting SRV records for mensago.mensago.net: {}", testname,
						e.to_string())
				))
			}
		};

		let mut fake_handler = FakeDNSHandler::new();
		let records = match fake_handler.lookup_srv(
			&String::from("_mensago._tcp.example.com.")) {
			
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting fake SRV records for example.com: {}", testname,
						e.to_string())
				))
			}
		};

		if records.len() != 2 {
			return Err(MensagoError::ErrProgramException(
				format!("{}: fake record count mismatch: wanted 2, got {}", testname, records.len())
			))
		}
		
		Ok(())
	}

	#[test]
	fn test_lookup_txt() -> Result<(), MensagoError> {
		let testname = "test_lookup_txt";

		let mut real_handler = DNSHandler::new_default().unwrap();

		// mensago.net is currently used for testing and development purposes, so we can count
		// on this returning specific values
		let records = match real_handler.lookup_txt(
			&Domain::from("mensago.mensago.net").unwrap()) {
			
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting TXT records for mensago.net: {}", testname, e.to_string())
				))
			}
		};

		if records.len() != 2 {
			return Err(MensagoError::ErrProgramException(
				format!("{}: record count mismatch: wanted 2, got {}", testname, records.len())
			))
		}

		let mut fake_handler = FakeDNSHandler::new();
		let records = match fake_handler.lookup_txt(
			&Domain::from("mensago.mensago.net").unwrap()) {
			
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting fake TXT records for mensago.net: {}", testname,
						e.to_string())
				))
			}
		};

		if records.len() != 2 {
			return Err(MensagoError::ErrProgramException(
				format!("{}: fake record count mismatch: wanted 2, got {}", testname, records.len())
			))
		}

		Ok(())
	}

	#[test]
	fn test_lookup_mgmtrec() -> Result<(), MensagoError> {
		let testname = "test_lookup_mgmtrec";

		let mut dh = FakeDNSHandler::new();
		let rec = match get_mgmt_record(&Domain::from("example.com").unwrap(), &mut dh) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting fake mgmt record for example.com: {}", testname,
						e.to_string())
				))
			}
		};
		
		if rec.pvk.to_string() != "ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*" ||
			rec.ek.to_string() != "CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az" {
			return Err(MensagoError::ErrProgramException(
				format!("{}: fake mgmt record value mismatch:\n pvk:{} ek:{}", testname,
					rec.pvk, rec.ek)
			))
		}

		Ok(())
	}

	#[test]
	fn test_get_server_config() -> Result<(), MensagoError> {
		let testname = "test_get_server_config";

		// Regular success case

		let mut dh = FakeDNSHandler::new();
		let mut fakeconfig = match get_server_config(&Domain::from("example.com").unwrap(), &mut dh) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting fake SRV-based record for example.com: {}", testname,
						e.to_string())
				))
			}
		};
		let mut fakerec = &fakeconfig[0];
		if fakerec != &(ServiceConfigRecord {
				server: Domain::from("mensago1.example.com").unwrap(),
				port: 2001,
				priority: 0,
			}) {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error fake SRV value mismatch", testname)
				))
		}

		// Test case: no SRV record

		dh.push_error(FakeDNSError::NotFound);
		fakeconfig = match get_server_config(&Domain::from("example.com").unwrap(), &mut dh) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting fake A-based record for example.com: {}", testname,
						e.to_string())
				))
			}
		};
		fakerec = &fakeconfig[0];
		if fakerec != &(ServiceConfigRecord {
				server: Domain::from("mensago.example.com").unwrap(),
				port: 2001,
				priority: 0,
			}) {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error fake A value mismatch", testname)
				))
		}

		Ok(())
	}
}
