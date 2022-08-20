use std::net::{IpAddr, SocketAddr, ToSocketAddrs, Ipv4Addr, Ipv6Addr};
use trust_dns_client::client::SyncClient;
use trust_dns_client::tcp::TcpClientConnection;
use trust_dns_client::udp::UdpClientConnection;
use eznacl::CryptoString;
use libkeycard::Domain;
use crate::MensagoError;

/// The DNSHandler trait is an abstraction trait for easy unit testing
pub trait DNSHandlerT {
	fn set_server(&mut self, addr: SocketAddr, udp: bool) -> Result<(), MensagoError>;
	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError>;
	fn lookup_aaaa(&self, d: &Domain) -> Result<IpAddr, MensagoError>;
	fn lookup_txt(&self, d: &Domain) -> Result<Vec<String>, MensagoError>;
}

/// The DNSHandler type provides a simple DNS API specific to the needs of Mensago clients
pub struct DNSHandler {
	server: SocketAddr,
	udp: bool,
}

impl DNSHandler {

	pub fn new(server: SocketAddr, udp: bool) -> DNSHandler {
		DNSHandler {
			server,
			udp
		}
	}

}

impl DNSHandlerT for DNSHandler {

	fn set_server(&mut self, addr: SocketAddr, udp: bool) -> Result<(), MensagoError> {

		self.server = addr;
		self.udp = udp;

		Err(MensagoError::ErrUnimplemented)
	}

	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			if a.is_ipv4() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}

	fn lookup_aaaa(&self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			if a.is_ipv6() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}

	fn lookup_txt(&self, d: &Domain) -> Result<Vec<String>, MensagoError> {
	
		// Implement DNSHandler::lookup_txt()

		Err(MensagoError::ErrUnimplemented)
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

	fn set_server(&mut self, _addr: SocketAddr, _udp: bool) -> Result<(), MensagoError> {
		Ok(())
	}

	fn lookup_a(&self, _d: &Domain) -> Result<IpAddr, MensagoError> {
		Ok(IpAddr::V4(Ipv4Addr::new(127,0,0,1)))
	}

	fn lookup_aaaa(&self, _d: &Domain) -> Result<IpAddr, MensagoError> {
		Ok(IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,1)))
	}

	fn lookup_txt(&self, d: &Domain) -> Result<Vec<String>, MensagoError> {
		Ok(vec![
			String::from("pvk=ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*"),
			String::from("ek=CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"),
		])
	}
}

pub struct DNSMgmtRecord {
	pvk: CryptoString,
	svk: Option<CryptoString>,
	ek: CryptoString,
	hash: CryptoString,
}

pub fn get_mgmt_record<D: DNSHandlerT>(d: &Domain, dh: D) -> Result<DNSMgmtRecord, MensagoError> {

	// TODO: Implement get_mgmt_record()

	Err(MensagoError::ErrUnimplemented)
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
		let testname = "test_real_lookup_a";

		let example_com = IpAddr::V4(Ipv4Addr::new(93,184,216,34));
		let real_handler = DNSHandler::new("1.1.1.1:53".parse().unwrap(), true);
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
		let testname = "test_real_lookup_aaaa";

		let example_com = IpAddr::V6(Ipv6Addr::new(0x2606,0x2800,0x220,1,0x248,0x1893,0x25c8,0x1946));
		let real_handler = DNSHandler::new("1.1.1.1:53".parse().unwrap(), true);
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
}