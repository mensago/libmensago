use std::{collections::VecDeque, fmt};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use trust_dns_resolver::{Resolver,config::*};
use libkeycard::Domain;
use crate::MensagoError;

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct ServiceConfigRecord {
	pub server: Domain,
	pub port: u16,
	pub priority: u16,
}

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
