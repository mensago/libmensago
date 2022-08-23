use std::net::{IpAddr, SocketAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use trust_dns_resolver::{Resolver,config::*};
use eznacl::CryptoString;
use libkeycard::Domain;
use crate::MensagoError;

/// The DNSHandler trait is an abstraction trait for easy unit testing
pub trait DNSHandlerT {
	fn set_server(&mut self, config: ResolverConfig, opts: ResolverOpts) -> Result<(), MensagoError>;
	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError>;
	fn lookup_aaaa(&self, d: &Domain) -> Result<IpAddr, MensagoError>;
	fn lookup_txt(&self, d: &Domain) -> Result<Vec<String>, MensagoError>;
	fn lookup_srv(&self, d: &Domain) -> Result<Vec<(String, u16, usize)>, MensagoError>;
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
	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			if a.is_ipv4() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}

	/// Resolves a DNS domain to an IPv6 address.
	fn lookup_aaaa(&self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			if a.is_ipv6() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}

	/// Returns all service records for the specified domain
	fn lookup_srv(&self, d: &Domain) -> Result<Vec<(String, u16, usize)>, MensagoError> {
		
		// TODO: Implement DNSHandler::lookup_srv
		Err(MensagoError::ErrUnimplemented)
	}

	/// Returns all text records for the specified domain
	fn lookup_txt(&self, d: &Domain) -> Result<Vec<String>, MensagoError> {
		
		let mut out = Vec::<String>::new();

		let result = self.resolver.txt_lookup(&d.to_string())?;
		for record in result.iter() {
			out.push(record.to_string())
		}

		Ok(out)
	}
}

/// The FakeDNSHandler type provides mock DNS information for unit testing purposes
pub struct FakeDNSHandler {

}

impl FakeDNSHandler {

	pub fn new() -> FakeDNSHandler {
		FakeDNSHandler {  }
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
	fn lookup_a(&self, _d: &Domain) -> Result<IpAddr, MensagoError> {
		Ok(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
	}

	/// Normally turns a DNS domain into an IPv6 address. This implementation always returns
	/// ::1.
	fn lookup_aaaa(&self, _d: &Domain) -> Result<IpAddr, MensagoError> {
		Ok(IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,1)))
	}

	/// Normally returns all service records for a domain. This implementation always returns
	/// mensago.example.com on port 2001 with a TTL of 86400.
	fn lookup_srv(&self, _d: &Domain) -> Result<Vec<(String, u16, usize)>, MensagoError> {
		Ok(vec![
			(String::from("mensago.example.com"), 2001, 86400),
		])
	}

	/// Normally returns all text records for a domain. This implementation always returns two
	/// records which contain a PVK and an EK Mensago config item, respectively.
	fn lookup_txt(&self, _d: &Domain) -> Result<Vec<String>, MensagoError> {
		Ok(vec![
			String::from("pvk=ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*"),
			String::from("ek=CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"),
		])
	}
}

pub struct ServerConfigRecord {
	server: Domain,
	port: u16,
	priority: u16,
}

pub fn get_server_config(d: &Domain) -> Result<Vec<ServerConfigRecord>, MensagoError> {

	// TODO: Implement get_server_config()

	return Err(MensagoError::ErrUnimplemented)
}

pub struct DNSMgmtRecord {
	pub pvk: CryptoString,
	pub svk: Option<CryptoString>,
	pub ek: CryptoString,
	pub tls: Option<CryptoString>,
}

pub fn get_mgmt_record<D: DNSHandlerT>(d: &Domain, dh: &D) -> Result<DNSMgmtRecord, MensagoError> {

	let domstr = d.to_string();
	let domparts: Vec::<&str> = domstr.split(".").collect();
	
	// This is probably a hostname, so we'll check just the hostname for records
	if domparts.len() == 1 {
		return parse_txt_records(&dh.lookup_txt(d)?)
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
		let real_handler = DNSHandler::new_default().unwrap();
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
		let fake_handler = FakeDNSHandler::new();
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
		let real_handler = DNSHandler::new_default().unwrap();
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
		let fake_handler = FakeDNSHandler::new();
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
	fn test_lookup_txt() -> Result<(), MensagoError> {
		let testname = "test_lookup_txt";

		let real_handler = DNSHandler::new_default().unwrap();

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

		let fake_handler = FakeDNSHandler::new();
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

		let dh = FakeDNSHandler::new();
		let rec = match get_mgmt_record(&Domain::from("example.com").unwrap(), &dh) {
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
}
