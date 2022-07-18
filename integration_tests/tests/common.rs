//! This module contains setup functions needed by the integration tests

// THESE KEYS ARE STORED ON GITLAB! DO NOT USE THESE FOR ANYTHING EXCEPT UNIT TESTS!!

// Test Organization Information

// Name: Example.com
// Contact-Admin: ae406c5e-2673-4d3e-af20-91325d9623ca/acme.com
// Support and Abuse accounts are forwarded to Admin
// Language: en

// Initial Organization Primary Signing Key: {UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_
// Initial Organization Primary Verification Key: r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*
// Initial Organization Primary Verification Key Hash: 
// BLAKE2B-256:ag29av@TUvh-V5KaB2l}H=m?|w`}dvkS1S1&{cMo

// Initial Organization Encryption Key: SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az
// Initial Organization Encryption Key Hash: BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W
// Initial Organization Decryption Key: WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o

// THESE KEYS ARE STORED ON GITLAB! DO NOT USE THESE FOR ANYTHING EXCEPT UNIT TESTS!!

use libmensago::*;
use std::{path::PathBuf, fs};
use toml_edit::{Document, value};

/// Loads the Mensago server configuration from the config file
pub fn load_server_config(testmode: bool) -> Result<Document, MensagoError> {

	let config_file_path: PathBuf;

	if testmode {
		if cfg!(windows) {
			config_file_path = PathBuf::from("C:\\ProgramData\\mensagod\\testconfig.toml");
		} else {
			config_file_path = PathBuf::from("/etc/mensagod/testconfig.toml");
		}
	} else {
		if cfg!(windows) {
			config_file_path = PathBuf::from("C:\\ProgramData\\mensagod\\serverconfig.toml");
		} else {
			config_file_path = PathBuf::from("/etc/mensagod/serverconfig.toml");
		}
	}

	let mut out: toml_edit::Document;
	if config_file_path.exists() {

		let rawdata = fs::read_to_string(config_file_path)?;
		out = match rawdata.parse::<Document>() {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("error parsing server config file: {}", e.to_string())
				))
			}
		};

	} else {
		return Err(MensagoError::ErrProgramException(String::from("server config file not found")))
	}

	// Add defaults for missing configuration values
	let default_string_values = [
		("network", "listen_ip", "127.0.0.1"),
		("database", "engine", "postgresql"),
		("database", "ip", "127.0.0.1"),

		// TODO make database.port an integer, not string
		("database", "port", "5432"),
		("database", "name", "mensago"),
		("database", "user", "mensago"),
		("database", "password", "CHANGEME"),

		("global", "registration", "private"),
		("global", "registration_subnet", "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8"),
		("global", "registration_subnet6", "fe80::/10"),

		("security", "diceware_wordlist", "eff_short_prefix"),
	];
	for s in default_string_values {
		if out.get(s.0).is_none() || out.get(s.1).is_none() {
			out[s.0][s.1] = value(s.2)
		}
	}

	let default_integer_values = [
		("network", "port", 2001),
		("global", "default_quota", 0),
		("performance", "max_file_size", 50),
		("performance", "max_message_size", 50),
		("performance", "max_sync_age", 7),
		("performance", "max_delivery_threads", 100),
		("performance", "max_client_threads", 10_000),
		("performance", "keycard_cache_size", 5_000),

		("security", "diceware_wordcount", 6),
		("security", "failure_delay_sec", 3),
		("security", "max_failures", 5),
		("security", "lockout_delay_min", 15),
		("security", "registration_delay_min", 15),
		("security", "password_reset_min", 60),
	];

	for i in default_integer_values {
		if out.get(i.0).is_none() || out.get(i.1).is_none() {
			out[i.0][i.1] = value(i.2)
		}
	}

	Ok(out)
}

#[cfg(test)]
mod tests {
	use libmensago::*;
	use super::*;

	#[test]
	fn test_load_server_config() -> Result<(), MensagoError> {
		
		let config = load_server_config(false)?;

		println!("{:#?}", config);

		println!("max_failures: {}", config["security"].get("max_failures").unwrap()
			.as_integer().unwrap());
		Ok(())
	}
}

// TODO: finish porting integration test setup code from pymensago

// TODO: write setup code tests

