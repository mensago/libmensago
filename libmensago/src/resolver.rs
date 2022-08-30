use std::{collections::VecDeque, fmt};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use trust_dns_resolver::{Resolver,config::*};
use eznacl::CryptoString;
use libkeycard::Domain;
use crate::{MensagoError, MConn, ServerConnection};

/// The DNSHandler trait is an abstraction trait for easy unit testing
pub trait DNSHandlerT {

	/// Sets configuration for which server will be used to resolve queries and how.
	fn set_server(&mut self, config: ResolverConfig, opts: ResolverOpts) -> Result<(), MensagoError>;

	/// Turns a domain into an IPv4 address
	fn lookup_a(&mut self, d: &Domain) -> Result<IpAddr, MensagoError>;

	/// Turns a domain into an IPv6 address
	fn lookup_aaaa(&mut self, d: &Domain) -> Result<IpAddr, MensagoError>;

	/// Returns all text records for a specific domain. This call is primarily intended for
	/// Mensago management record lookups.
	fn lookup_txt(&mut self, d: &Domain) -> Result<Vec<String>, MensagoError>;

	/// Returns service records for a specific domain. The information returned consists of a
	/// series of tuples containing the domain, the port, and the Time To Live. This call
	/// internally sorts the records by priority and weight in descending order such that the
	/// first entry in the returned list has the highest priority.
	fn lookup_srv(&mut self, d: &str) -> Result<Vec<ServiceConfigRecord>, MensagoError>;
}

/// The DNSHandler type provides a simple DNS API specific to the needs of Mensago clients
pub struct DNSHandler {
	resolver: Resolver,
}

impl DNSHandler {

	/// Creates a new DNSHandler which uses the system resolver on POSIX platforms and Quad9 on
	/// Windows.
	pub fn new_default() -> Result<DNSHandler, MensagoError> {

		if cfg!(windows) {
			Ok(DNSHandler {
				resolver: Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?
			})
		} else {
			Ok(DNSHandler {
				resolver: Resolver::from_system_conf()?
			})
		}
	}

	/// Creates a new DNSHandler instance with a specified configuration, corresponding to
	/// `set_server()`.
	pub fn new(config: ResolverConfig, opts: ResolverOpts) -> Result<DNSHandler, MensagoError> {

		Ok(DNSHandler {
			resolver: Resolver::new(config, opts)?
		})
	}

}

impl DNSHandlerT for DNSHandler {

	/// Sets the server and configuration information.
	fn set_server(&mut self, config: ResolverConfig, opts: ResolverOpts) -> Result<(), MensagoError> {

		self.resolver = Resolver::new(config, opts)?;
		Ok(())
	}

	/// Resolves a DNS domain to an IPv4 address.
	fn lookup_a(&mut self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			if a.is_ipv4() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}

	/// Resolves a DNS domain to an IPv6 address.
	fn lookup_aaaa(&mut self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			if a.is_ipv6() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}

	/// Returns all service records for the specified domain
	fn lookup_srv(&mut self, d: &str) -> Result<Vec<ServiceConfigRecord>, MensagoError> {

		let mut out = Vec::<ServiceConfigRecord>::new();
		
		let result = match self.resolver.srv_lookup(d) {
			Ok(v) => v,
			Err(_) => {
				return Err(MensagoError::ErrNotFound)
			}
		};

		// We have at least one record here, so the first thing is to sort the list by priority
		// and then weight. From there we can construct the list of ServiceConfigRecord objects
		// to return to the caller.

		let mut records: Vec<&trust_dns_proto::rr::rdata::srv::SRV> = result.iter().collect();
		records.sort_by(|a, b| {
			if a.priority() < b.priority() {
				return std::cmp::Ordering::Less
			}
			if a.priority() > b.priority() {
				return std::cmp::Ordering::Greater
			}
			
			a.weight().cmp(&b.weight())
		});

		let mut priority: u16 = 0;
		for record in records.iter() {

			// The Trust DNS crates work best with FQDNs -- domains ending in a period. We don't
			// do that here. ;)
			let target = record.target().to_string();
			let trimmed = target.trim_end_matches(".");
			
			// We received records from the server, but it's no guarantee that they're safe to use.
			// If the server given doesn't actually work, then it's a possibly-intentional
			// misconfiguration. Skip the record and check afterward to see if we have anything
			// valid.
			let s = match Domain::from(trimmed) {
				Some(v) => v,
				None => {
					continue
				}
			};

			out.push(ServiceConfigRecord{
				server: s,
				port: record.port(),
				priority,
			});

			priority += 1;
		}

		if out.len() == 0 {
			// We were given records, but none of them were valid, so bomb out here
			return Err(MensagoError::ErrBadValue)
		}
		
		Ok(out)
	}

	/// Returns all text records for the specified domain
	fn lookup_txt(&mut self, d: &Domain) -> Result<Vec<String>, MensagoError> {
		
		let mut out = Vec::<String>::new();

		let result = match self.resolver.txt_lookup(&d.to_string()) {
			Ok(v) => v,
			Err(_) => {
				return Err(MensagoError::ErrNotFound)
			}
		};

		for record in result.iter() {
			out.push(record.to_string())
		}

		Ok(out)
	}
}

/// This enum is for simulating different  FakeDNSHandler error conditions
#[derive(Debug, Clone, Copy)]
pub enum FakeDNSError {
	Empty,
	NoResponse,
	Misconfig,
	NotFound,
}

impl fmt::Display for FakeDNSError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			FakeDNSError::Empty => { write!(f, "Empty")	},
			FakeDNSError::Misconfig => { write!(f, "Misconfig")	},
			FakeDNSError::NoResponse => { write!(f, "NoResponse")	},
			FakeDNSError::NotFound => { write!(f, "NotFound")	},
		}
	}
}

/// The FakeDNSHandler type provides mock DNS information for unit testing purposes
pub struct FakeDNSHandler {
	error_list: VecDeque<FakeDNSError>,
}

impl FakeDNSHandler {

	pub fn new() -> FakeDNSHandler {
		FakeDNSHandler { 
			error_list: VecDeque::new()
		}
	}

	pub fn push_error(&mut self, e: FakeDNSError) {
		self.error_list.push_back(e)
	}
}

impl DNSHandlerT for FakeDNSHandler {

	/// Normally sets the server and configuration information. This call for FakeDNSHandler is
	/// a no-op
	fn set_server(&mut self, _config: ResolverConfig, _opts: ResolverOpts)
	-> Result<(), MensagoError> {
		Ok(())
	}

	/// Normally turns a DNS domain into an IPv4 address. This implementation always returns
	/// 127.0.0.1.
	fn lookup_a(&mut self, _d: &Domain) -> Result<IpAddr, MensagoError> {

		match self.error_list.pop_front() {
			Some(e) => {
				match e {
					FakeDNSError::NoResponse => { return Err(MensagoError::ErrNetworkError) },
					FakeDNSError::Misconfig => { return Ok(IpAddr::V4(Ipv4Addr::new(0,0,0,0))) },
					FakeDNSError::Empty => { return Err(MensagoError::ErrEmptyData) },
					FakeDNSError::NotFound => { return Err(MensagoError::ErrNotFound) },
				}
			},
			None => (),
		}

		Ok(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
	}

	/// Normally turns a DNS domain into an IPv6 address. This implementation always returns
	/// ::1.
	fn lookup_aaaa(&mut self, _d: &Domain) -> Result<IpAddr, MensagoError> {

		match self.error_list.pop_front() {
			Some(e) => {
				match e {
					FakeDNSError::NoResponse => { return Err(MensagoError::ErrNetworkError) },
					FakeDNSError::Misconfig => { return Ok(IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,0))) },
					FakeDNSError::Empty => { return Err(MensagoError::ErrEmptyData) },
					FakeDNSError::NotFound => { return Err(MensagoError::ErrNotFound) },
				}
			},
			None => (),
		}

		Ok(IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,1)))
	}

	/// Normally returns all service records for a domain. This implementation always returns
	/// mensago.example.com on port 2001 with a TTL of 86400.
	fn lookup_srv(&mut self, _d: &str) -> Result<Vec<ServiceConfigRecord>, MensagoError> {

		match self.error_list.pop_front() {
			Some(e) => {
				match e {
					FakeDNSError::NoResponse => { return Err(MensagoError::ErrNetworkError) },
					FakeDNSError::Empty => { return Err(MensagoError::ErrEmptyData) },
					FakeDNSError::NotFound => { return Err(MensagoError::ErrNotFound) },
					FakeDNSError::Misconfig => { 
						return Ok(vec![
							ServiceConfigRecord {
								server: Domain::from("myhostname").unwrap(),
								port: 0,
								priority: 100,
							},
						])
					},
				}
			},
			None => (),
		}

		Ok(vec![
			ServiceConfigRecord {
				server: Domain::from("mensago1.example.com").unwrap(),
				port: 2001,
				priority: 0,
			},
			ServiceConfigRecord {
				server: Domain::from("mensago2.example.com").unwrap(),
				port: 2001,
				priority: 1,
			},
		])
	}

	/// Normally returns all text records for a domain. This implementation always returns two
	/// records which contain a PVK and an EK Mensago config item, respectively.
	fn lookup_txt(&mut self, _d: &Domain) -> Result<Vec<String>, MensagoError> {

		match self.error_list.pop_front() {
			Some(e) => {
				match e {
					FakeDNSError::NoResponse => { return Err(MensagoError::ErrNetworkError) },
					FakeDNSError::Empty => { return Err(MensagoError::ErrEmptyData) },
					FakeDNSError::NotFound => { return Err(MensagoError::ErrNotFound) },
					FakeDNSError::Misconfig => { 
						return Ok(vec![
							String::from("pvk=K12:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*"),
							String::from("svk=CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"),
						])
					},
				}
			},
			None => (),
		}

		Ok(vec![
			String::from("pvk=ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*"),
			String::from("ek=CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"),
		])
	}
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct ServiceConfigRecord {
	pub server: Domain,
	pub port: u16,
	pub priority: u16,
}

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
	match conn.connect(tempdom.as_string(), "2001") {
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

}

impl KCResolver {

	pub fn new(profile_path: &str) -> Result<KCResolver, MensagoError> {

		if profile_path.len() == 0 {
			return Err(MensagoError::ErrEmptyData)
		}

		// TODO: Implement KCResolver::new()

		Err(MensagoError::ErrUnimplemented)
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
					format!("{}: error getting fake server for example.com: {}", testname,
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
					format!("{}: error fake server config value mismatch", testname)
				))
		}

		// Test case: no SRV record

		dh.push_error(FakeDNSError::NotFound);
		fakeconfig = match get_server_config(&Domain::from("example.com").unwrap(), &mut dh) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting fake server for example.com: {}", testname,
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
					format!("{}: error fake server config value mismatch", testname)
				))
		}

		// TODO: Implement test_get_server_config()
		
		Ok(())
	}
}
