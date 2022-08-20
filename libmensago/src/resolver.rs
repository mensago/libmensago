use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use eznacl::CryptoString;
use libkeycard::Domain;
use crate::MensagoError;

/// The DNSHandler trait is an abstraction trait for easy unit testing
pub trait DNSHandlerT {
	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError>;
}

/// The DNSHandler type provides a simple DNS API specific to the needs of Mensago clients
pub struct DNSHandler {

}

impl DNSHandler {

	pub fn new() -> DNSHandler {
		DNSHandler {  }
	}

}

impl DNSHandlerT for DNSHandler {

	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError> {
		
		let addresses: Vec<SocketAddr> = format!("{}:443", d.as_string()).to_socket_addrs()?.collect();

		for a in addresses {
			println!("{:?}", a);
			if a.is_ipv4() {
				return Ok(a.ip())
			}
		}
		
		Err(MensagoError::ErrNotFound)
	}
}

/// The FakeDNSHandler type provides mock DNS information for unit testing purposes
pub struct FakeDNSHandler {

}

impl DNSHandlerT for FakeDNSHandler {

	fn lookup_a(&self, d: &Domain) -> Result<IpAddr, MensagoError> {

		// TODO: Implement FakeDNSHandler::lookup_a()

		Err(MensagoError::ErrUnimplemented)
	}
}

pub struct DNSMgmtRecord {
	pvk: CryptoString,
	svk: Option<CryptoString>,
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
	use std::net::{IpAddr, Ipv4Addr};

	#[test]
	fn test_real_lookup_a() -> Result<(), MensagoError> {
		let testname = "test_real_lookup_a";

		let example_com = IpAddr::V4(Ipv4Addr::new(93,184,216,34));
		let real_handler = DNSHandler::new();
		let returned_ip = match real_handler.lookup_a(&Domain::from("example.com").unwrap()) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error looking up address: {}", testname, e.to_string())
				))
			}
		};
		assert_eq!(returned_ip, example_com);

		Ok(())
	}
}