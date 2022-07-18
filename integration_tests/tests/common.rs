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
use toml;

/// Loads the Mensago server configuration from the config file
pub fn load_server_config() -> Result<toml::Value, MensagoError> {

	let config_file_path: PathBuf;

	if cfg!(windows) {
		config_file_path = PathBuf::from("C:\\ProgramData\\mensagod\\serverconfig.toml");
	} else {
		config_file_path = PathBuf::from("/etc/mensagod/serverconfig.toml");
	}

	let out: toml::Value;
	if config_file_path.exists() {

		let rawdata = fs::read_to_string(config_file_path)?;
		out = match rawdata.parse::<toml::Value>() {
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

	Ok(out)
}

#[cfg(test)]
mod tests {
	use libmensago::*;
	use super::*;

	#[test]
	fn test_load_server_config() -> Result<(), MensagoError> {
		
		let config = load_server_config()?;

		println!("{:#?}", config);

		println!("{}", config["database"].get("password").unwrap().as_str().unwrap());
		Ok(())
	}
}

// TODO: finish porting integration test setup code from pymensago

// TODO: write setup code tests

