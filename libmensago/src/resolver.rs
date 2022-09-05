use chrono::prelude::*;
use eznacl::CryptoString;
use libkeycard::*;
use std::path::PathBuf;
use crate::*;

/// This function attempts to obtain Mensago server configuration information for the specified
/// domain using the process documented in the spec:
/// 
/// 1. Check for an SRV record with the service type `_mensago._tcp`, and use the supplied FQDN
/// and port if it exists
/// 2. Perform an A or AAAA lookup for `mensago.subdomain.example.com`
/// 3. Perform an A or AAAA lookup for `mensago.example.com`
/// 4. Attempt to connect to `example.com`
/// 
/// If all of these checks fail, then the domain is assumed to not offer Mensago services and
/// MensagoError::ErrNotFound will be returned.
pub fn get_server_config<DH: DNSHandlerT>(d: &Domain, dh: &mut DH)
-> Result<Vec<ServiceConfigRecord>, MensagoError> {

	match dh.lookup_srv(&format!("_mensago._tcp.{}", d.as_string())) {
		Ok(v) => { return Ok(v) },
		Err(_) => (),
	};

	let mut tempdom = d.clone();
	loop {
		tempdom.push("mensago").unwrap();

		match dh.lookup_a(&d) {
			Ok(_) => {
				return Ok(vec![
					ServiceConfigRecord {
						server: tempdom.clone(),
						port: 2001,
						priority: 0,
					}
				])
			},
			Err(_) => (),
		}

		match dh.lookup_aaaa(&d) {
			Ok(_) => {
				return Ok(vec![
					ServiceConfigRecord {
						server: tempdom.clone(),
						port: 2001,
						priority: 0,
					}
				])
			},
			Err(_) => (),
		}

		tempdom.pop().unwrap();

		if tempdom.parent().is_none() {
			break
		}

		tempdom.pop().unwrap();
	}

	// Having gotten this far, we have only one other option: attempt to connect to the domain
	// on port 2001.
	let mut conn = ServerConnection::new();
	match conn.connect(tempdom.as_string(), 2001) {
		Ok(_) => {
			return Ok(vec![
				ServiceConfigRecord {
					server: tempdom.clone(),
					port: 2001,
					priority: 0,
				}
			])
		},
		Err(_) => (),
	}

	Err(MensagoError::ErrNotFound)
}

pub struct DNSMgmtRecord {
	pub pvk: CryptoString,
	pub svk: Option<CryptoString>,
	pub ek: CryptoString,
	pub tls: Option<CryptoString>,
}

pub fn get_mgmt_record<DH: DNSHandlerT>(d: &Domain, dh: &mut DH) -> Result<DNSMgmtRecord, MensagoError> {

	let domstr = d.to_string();
	let domparts: Vec::<&str> = domstr.split(".").collect();
	
	// This is probably a hostname, so we'll check just the hostname for records
	if domparts.len() == 1 {
		return parse_txt_records(&mut dh.lookup_txt(d)?)
	}

	let mut out: Option<DNSMgmtRecord> = None;
	for i in 0..domparts.len() - 1 {

		let mut testparts = vec!["mensago"];
		for i in i..domparts.len() {
			testparts.push(domparts[i])
		}

		let testdom = match Domain::from(&testparts.join(".")) {
			Some(v) => v,
			None => {
				return Err(MensagoError::ErrBadValue)
			}	
		};
		
		let records = match dh.lookup_txt(&testdom) {
			Ok(v) => v,
			Err(_) => {
				continue
			}
		};

		out = Some(parse_txt_records(&records)?);
	}

	match out {
		Some(v) => Ok(v),
		None => {
			Err(MensagoError::ErrNotFound)
		}
	}
}

// This private function just finds the management record items in a list of TXT records
fn parse_txt_records(records: &Vec::<String>) -> Result<DNSMgmtRecord, MensagoError> {

	// This seemlingly pointless construct ensures that we have all the necessary information if,
	// say, the admin put 2 management record items in a TXT record and put another in a second
	// record because they ran out of space in the first one
	let recordstr = records.join(" ");
	let parts = recordstr.split(" ");

	// The four possible record items. The PVK and EK items are required.
	let mut pvk: Option<CryptoString> = None;
	let mut svk: Option<CryptoString> = None;
	let mut ek: Option<CryptoString> = None;
	let mut tls: Option<CryptoString> = None;
	for part in parts {

		if part.len() < 5 {
			return Err(MensagoError::ErrBadValue)
		}

		match part {
			x if x.to_lowercase().starts_with("pvk=") => {
				pvk = CryptoString::from(&x[4..])
			},
			x if x.to_lowercase().starts_with("svk=") => {
				svk = CryptoString::from(&x[4..])
			},
			x if x.to_lowercase().starts_with("ek=") => {
				ek = CryptoString::from(&x[3..])
			},
			x if x.to_lowercase().starts_with("tls=") => {
				tls = CryptoString::from(&x[4..])
			},
			_ => (),
		}
	}

	if pvk.is_none() || ek.is_none() {
		return Err(MensagoError::ErrNotFound)
	}

	Ok(DNSMgmtRecord{
		pvk: pvk.unwrap(),
		svk,
		ek: ek.unwrap(),
		tls,
	})
}

/// A caching keycard resolver type
pub struct KCResolver {
	dbpath: PathBuf,
}

impl KCResolver {

	/// Creates a new resolver working out of the at the specified profile
	pub fn new(profile_path: &PathBuf) -> Result<KCResolver, MensagoError> {

		if !profile_path.exists() {
			return Err(MensagoError::ErrNotFound)
		}

		let mut storage = profile_path.clone();
		storage.push("storage.db");
		if !storage.exists() {
			return Err(MensagoError::ErrNotFound)
		}

		return Ok(KCResolver {
			dbpath: storage,
		})
	}

	/// Returns a keycard belonging to the specified owner. To obtain an organization's keycard,
	/// pass a domain, e.g. `example.com`. Otherwise obtain a user's keycard by passing either the
	/// user's Mensago address or its workspace address. When `force_update` is true, a lookup is
	/// forced and the cache is updated regardless of the keycard's TTL expiration status.
	pub fn get_card<DH: DNSHandlerT>(&mut self, owner: &str, dh: &mut DH, force_update: bool)
	-> Result<Keycard, MensagoError> {

		// First, determine the type of owner. A domain will be passed for an organization, and for
		// a user card a Mensago address or a workspace address will be given.
		let domain: Domain;
		let owner_type: EntryType;

		let isorg = Domain::from(owner);
		if isorg.is_some() {
			owner_type = EntryType::Organization;
			domain = isorg.unwrap();
		
		} else {
			let isuser = MAddress::from(owner);
			if isuser.is_some() {
				owner_type = EntryType::User;
				domain = isuser.unwrap().domain.clone();
			} else {
				return Err(MensagoError::ErrBadValue)
			}
		}


		let dbconn = self.open_storage()?;
		let mut card: Option<Keycard> = None;
		
		if !force_update {
			card = self.get_card_from_db(&dbconn, owner, owner_type)?;
		}

		// If we got a card from the call, it means a successful cache hit and the TTL timestamp
		// hasn't been reached yet.
		if card.is_some() {
			return Ok(card.unwrap())
		}

		// If we've gotten this far, it means that the card isn't in the database cache, so resolve
		// the card, add it to the database's cache, and return it to the caller.

		let serverconfig = get_server_config(&domain, dh)?;
		if serverconfig.len() == 0 {
			return Err(MensagoError::ErrNoMensago)
		}

		let mut conn = ServerConnection::new();
		conn.connect(&serverconfig[0].server.to_string(), serverconfig[0].port)?;

		let card = match owner_type {
			EntryType::Organization => { orgcard(&mut conn, 1)? },
			EntryType::User => { usercard(&mut conn, 1)? },
			_ => {
				// We should never be here
				panic!("BUG: Bad owner type in KCResolver::get_card()")
			},
		};
		
		conn.disconnect()?;
		
		self.update_card_in_db(&dbconn, &card)?;
		Ok(card)
	}

	/// Obtains the workspace ID for a Mensago address
	pub fn resolve_address<DH: DNSHandlerT>(&mut self, addr: &MAddress, dh: &mut DH)
	-> Result<RandomID, MensagoError> {

		if addr.get_uid().get_type() == IDType::WorkspaceID {
			return Ok(RandomID::from(addr.get_uid().as_string())
				.expect("BUG: couldn't convert UID to WID in KCResolver::resolve_address()"))
		}

		let serverconfig = get_server_config(addr.get_domain(), dh)?;
		if serverconfig.len() == 0 {
			return Err(MensagoError::ErrNoMensago)
		}

		let ip = dh.lookup_a(&serverconfig[0].server)?;

		let mut conn = ServerConnection::new();

		conn.connect(&ip.to_string(), serverconfig[0].port)?;
		let wid = getwid(&mut conn, addr.get_uid(), Some(addr.get_domain()))?;
		conn.disconnect()?;

		Ok(wid)
	}

	/// Obtains a keycard from the database's cache if it exists
	fn get_card_from_db(&self, conn: &rusqlite::Connection, owner: &str, etype: EntryType)
	-> Result<Option<Keycard>, MensagoError> {

		let mut card = Keycard::new(etype);

		// This is an internal call and owner has already been validated once, so we don't have to
		// do it again. Likewise, we validate everything ruthlessly when data is brought in, so
		// because that's already been done once, we don't need to do it again here -- just create
		// entries from each row and add them to the card.

		// A huge chunk of rusqlite-related code just to add the entries to the card. :(

		let mut stmt = conn.prepare("SELECT entry FROM keycards WHERE owner=? ORDER BY 'index'")?;
		
		let mut rows = match stmt.query([owner]) {
			Ok(v) => v,
			Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
		};

		let mut option_row = match rows.next() {
			Ok(v) => v,
			Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
		};

		while option_row.is_some() {
			let row = option_row.unwrap();

			let entry = Entry::from(&row.get::<usize,String>(0).unwrap())?;
			card.entries.push(entry);

			option_row = match rows.next() {
				Ok(v) => v,
				Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
			};
		}

		if card.entries.len() < 1 {
			return Ok(None)
		}

		let current = card.get_current().unwrap();
		let mut stmt = conn.prepare("SELECT ttlexpires FROM keycards WHERE owner=?1 AND index=?2")?;
		let ttlstr = stmt.query_row([&owner, current.get_field("Index").unwrap().as_str()], |row| {
			Ok(row.get::<usize,String>(0).unwrap())
		})?;
		
		let exptime = match NaiveDate::parse_from_str(&ttlstr, "%Y%m%dT%H%M%SZ") {
			Ok(d) => d,
			Err(e) => {
				// We should never be here
				return Err(MensagoError::ErrProgramException(e.to_string()))
			}
		};

		let now = Utc::now().date().naive_utc();

		if now > exptime {
			Ok(None)
		} else {
			Ok(Some(card))
		}
	}

	/// Adds a keycard to the database's cache or updates it if it already exists
	fn update_card_in_db(&self, conn: &rusqlite::Connection, card: &Keycard)
	-> Result<(), MensagoError> {

		let current = match card.get_current() {
			Some(v) => v,
			None => { return Err(MensagoError::ErrEmptyData) },
		};

		let owner = current.get_owner()?;

		match conn.execute("DELETE FROM keycards WHERE owner=?1", [&owner]) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			},
		}

		// Calculate the expiration time of the current entries
		let ttl_offset = current.get_field("Time-To-Live")
			.unwrap()
			.parse::<u16>()
			.unwrap();
		let ttl_expires = match Timestamp::new().with_offset(i64::from(ttl_offset)) {
			Some(v) => v,
			None => {
				return Err(MensagoError::ErrProgramException(
					String::from("BUG: timestamp generation failure in KCResolver::update_card_in_db")
				))
			}
		};

		for entry in card.entries.iter() {
			match conn.execute("INSERT INTO keycards(
				owner, index, type, entry, textentry, hash, expires, timestamp, ttlexpires)
				VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", [
					&owner,
					&entry.get_field("Index").unwrap(),
					&entry.get_field("Type").unwrap(),
					&entry.get_full_text("").unwrap(), 
					&entry.get_full_text("").unwrap(), 
					&entry.get_authstr("Hash").unwrap().to_string(),
					&entry.get_field("Expires").unwrap(),
					&entry.get_field("Timestamp").unwrap(),
					&ttl_expires.to_string(),
				]) {
			
				Ok(_) => (),
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				},
			};
		}

		Ok(())
	}

	pub fn open_storage(&self) -> Result<rusqlite::Connection, MensagoError> {
		match rusqlite::Connection::open_with_flags(&self.dbpath,
			rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE) {
				Ok(v) => Ok(v),
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
		}
	}
}


#[cfg(test)]
mod test {
    use crate::*;
	use libkeycard::Domain;
	use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
