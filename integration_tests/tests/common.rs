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

use eznacl::*;
use glob;
use libkeycard::*;
use libmensago::*;
use postgres::{Client, NoTls};
use std::collections::HashMap;
use std::fs;
use std::{path::PathBuf};
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
		if out.get(s.0).is_none() || out[s.0].get(s.1).is_none() {
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
		if out.get(i.0).is_none() || out[i.0].get(i.1).is_none() {
			out[i.0][i.1] = value(i.2)
		}
	}

	if cfg!(windows) {
		if out["global"].get("top_dir").is_none() {
			out["global"]["top_dir"] = value("C:\\ProgramData\\mensagodata");
		}
		if out["global"].get("workspace_dir").is_none() {
			out["global"]["workspace_dir"] = value("C:\\ProgramData\\mensagodata\\wsp");
		}
	} else {
		if out["global"].get("top_dir").is_none() {
			out["global"]["top_dir"] = value("/var/mensago");
		}
		if out["global"].get("workspace_dir").is_none() {
			out["global"]["workspace_dir"] = value("/var/mensago/wsp");
		}
	}

	Ok(out)
}

/// Empties and resets the server's database to start from a clean slate
pub fn setup_test(config: &Document) -> Result<postgres::Client, MensagoError> {

	// Reset the database to defaults.

	// postgres::connect requires escaping backslashes and single quotes.
	let password = config["database"]["password"]
		.as_str().unwrap()
		.replace(r#"\"#, r#"\\"#)
		.replace("'", r#"\'"#);
	
		let mut db = match Client::connect(&format!(
			"host='{}' port='{}' dbname='{}' user='{}' password='{}'",
			config["database"]["ip"].as_str().unwrap(),
			config["database"]["port"].as_str().unwrap(),
			config["database"]["name"].as_str().unwrap(),
			config["database"]["user"].as_str().unwrap(),
			password
		), NoTls) {
		Ok(v) => v,
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("couldn't connect to postgres database: {}", e.to_string())
			))
		}
	};

	match db.batch_execute("
	-- Drop all tables in the database
	DO $$ DECLARE
		r RECORD;
	BEGIN
		FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = current_schema()) LOOP
			EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
		END LOOP;
	END $$;

	-- Create new ones

	-- Lookup table for all workspaces. When any workspace is created, its wid is added here.
	-- userid is optional. wtype can be 'individual', 'sharing', 'group', or 'alias'
	CREATE TABLE workspaces(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
		uid VARCHAR(64), domain VARCHAR(255) NOT NULL, wtype VARCHAR(32) NOT NULL,
		status VARCHAR(16) NOT NULL, password VARCHAR(128));

	CREATE TABLE aliases(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, alias CHAR(292) NOT NULL);

	-- passcodes table is used for password resets
	CREATE TABLE passcodes(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE,
		passcode VARCHAR(128) NOT NULL, expires CHAR(16) NOT NULL);

	-- For logging different types of failures, such as failed usernanme entry or a server's failure
	-- to authenticate for delivery. Information stored here is to ensure that all parties which the
	-- server interacts with behave themselves.
	CREATE TABLE failure_log(rowid SERIAL PRIMARY KEY, type VARCHAR(16) NOT NULL,
		id VARCHAR(36), source VARCHAR(36) NOT NULL, count INTEGER,
		last_failure CHAR(16) NOT NULL, lockout_until CHAR(16));

	-- Preregistration information. Entries are removed upon successful account registration.
	CREATE TABLE prereg(rowid SERIAL PRIMARY KEY, wid VARCHAR(36) NOT NULL UNIQUE,
		uid VARCHAR(128) NOT NULL, domain VARCHAR(255) NOT NULL, regcode VARCHAR(128));

	-- Stores all entries in the keycard tree
	CREATE TABLE keycards(rowid SERIAL PRIMARY KEY, owner VARCHAR(292) NOT NULL,
		creationtime CHAR(16) NOT NULL, index INTEGER NOT NULL,
		entry VARCHAR(8192) NOT NULL, fingerprint VARCHAR(96) NOT NULL);

	-- Keycard information for the organization
	CREATE TABLE orgkeys(rowid SERIAL PRIMARY KEY, creationtime CHAR(16) NOT NULL, 
		pubkey VARCHAR(7000), privkey VARCHAR(7000) NOT NULL, 
		purpose VARCHAR(8) NOT NULL, fingerprint VARCHAR(96) NOT NULL);

	-- Disk quota tracking
	CREATE TABLE quotas(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL, usage BIGINT, quota BIGINT);

	-- For logging updates made to a workspace. This table is critical to device synchronization.
	-- The update_data field is specific to the update type.
	-- 
	-- Update Types
	-- 1: CREATE. An item has been created. update_data contains the path of the item created. Note
	--    that this applies both to files and directories
	-- 2: DELETE. An item has een deleted. update_data contains the path of the item created. Note
	--    that this applies both to files and directories. If a directory has been deleted, all of
	--	  its contents have also been deleted, which improves performance when large directories go
	--    away.
	-- 3: MOVE. An item has been moved. update_data contains two paths, the source and the
	--    destination. The source path contains the directory path, and in the case of a file, the
	--    file name. The destination contains only a folder path.
	-- 4: ROTATE. Keys have been rotated. update_data contains the path to the encrypted key storage
	--    package.

	CREATE TABLE updates(rowid SERIAL PRIMARY KEY, rid CHAR(36) NOT NULL, wid CHAR(36) NOT NULL,
		update_type INTEGER, update_data VARCHAR(2048), unixtime BIGINT);

	-- Information about individual workspaces

	CREATE TABLE iwkspc_folders(rowid SERIAL PRIMARY KEY, wid char(36) NOT NULL,
		serverpath VARCHAR(512) NOT NULL, clientpath VARCHAR(768) NOT NULL);

	-- Devices registered to each individual's workspace
	CREATE TABLE iwkspc_devices(rowid SERIAL PRIMARY KEY, wid CHAR(36) NOT NULL,
		devid CHAR(36) NOT NULL, devkey VARCHAR(1000) NOT NULL, lastlogin VARCHAR(32) NOT NULL, 
		status VARCHAR(16) NOT NULL);
	") {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error resetting postgres database: {}", e.to_string())
			))
		}
	}

	Ok(db)
}

// Adds basic data to the database as if setup had been run. It also rotates the org 
// keycard so that there are two entries. Returns data needed for tests, such as the keys
pub fn init_server(db: &mut postgres::Client) -> Result<HashMap<&'static str,String>, MensagoError> {

	// Start off by generating the org's root keycard entry and add to the database
	let mut orgcard = Keycard::new(&EntryType::Organization);
	let mut root_entry = Entry::new(EntryType::Organization)?;
	root_entry.set_fields(&vec![
		(String::from("Index"), String::from("1")),
		(String::from("Name"), String::from("Example, Inc.")),
		(String::from("Contact-Admin"), String::from("c590b44c-798d-4055-8d72-725a7942f3f6/example.com")),
		(String::from("Language"), String::from("en")),
		(String::from("Domain"), String::from("example.com")),
		(String::from("Primary-Verification-Key"),
			String::from("ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*")),
		(String::from("Encryption-Key"),
			String::from("CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az")),
	])?;

	let initial_ospair = SigningPair::from(
		&CryptoString::from("ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*").unwrap(),
		&CryptoString::from("ED25519:{UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_").unwrap());
	let initial_oepair = EncryptionPair::from(
		&CryptoString::from("CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az").unwrap(),
		&CryptoString::from("CURVE25519:WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o").unwrap());
	
	match root_entry.is_data_compliant() {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("root org entry not data compliant: {}", e.to_string())
			))
		}
	}

	match root_entry.hash("BLAKE3-256") {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("couldn't hash root org entry: {}", e.to_string())
			))
		}
	}
	
	match root_entry.sign("Organization-Signature", &initial_ospair) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("failed to sign root org entry: {}", e.to_string())
			))
		}
	}
	
	match root_entry.verify_signature("Organization-Signature", &initial_ospair) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("couldn't verify root org entry: {}", e.to_string())
			))
		}
	}
	
	match root_entry.is_compliant() {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("root org entry not compliant: {}", e.to_string())
			))
		}
	}

	orgcard.entries.push(root_entry);

	{	// Limit scope for access to root entry to enable chaining later

		let root_entry = &orgcard.entries[0];
		let index = match root_entry.get_field("Index")?.parse::<i32>() {
			Ok(v) => v,
			Err(e) => panic!("{}", e.to_string()),
		};
		match db.execute("INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) 
		VALUES('organization',$1,$2,$3,$4);", &[
			&root_entry.get_field("Timestamp")?,
			&index,
			&root_entry.get_full_text("")?,
			&root_entry.get_authstr("Hash")?.to_string(),
		]) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("error initializing keycard table: {}", e.to_string())
				))
			}
		}

		match db.execute("INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
		VALUES($1,$2,$3,'encrypt',$4);", &[
			&root_entry.get_field("Timestamp")?,
			&initial_oepair.get_public_str(),
			&initial_oepair.get_private_str(),
			&get_hash("BLAKE3-256", &initial_oepair.get_public_bytes())?.to_string(),
		]) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("error adding encryption keys to orgkeys table: {}", e.to_string())
				))
			}
		}

		match db.execute("INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
		VALUES($1,$2,$3,'sign',$4);", &[
			&root_entry.get_field("Timestamp")?,
			&initial_ospair.get_public_str(),
			&initial_ospair.get_private_str(),
			&get_hash("BLAKE3-256", &initial_ospair.get_public_bytes())?.to_string(),
		]) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("error adding signing keys to orgkeys table: {}", e.to_string())
				))
			}
		}
	}

	// Chain new entry to the root and add to the database

	let keys = match orgcard.chain(&initial_ospair, 365) {
		Ok(v) => (v),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error chaining org root entry: {}", e.to_string())
			))
		}
	};
	
	let new_entry = &orgcard.entries[1];
	let index = match new_entry.get_field("Index")?.parse::<i32>() {
		Ok(v) => v,
		Err(e) => panic!("{}", e.to_string()),
	};
	match db.execute("INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) 
	VALUES('organization',$1,$2,$3,$4);", &[
		&new_entry.get_field("Timestamp")?,
		&index,
		&new_entry.get_full_text("")?,
		&new_entry.get_authstr("Hash")?.to_string(),
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding updated entry to keycard table: {}", e.to_string())
			))
		}
	}

	match db.execute("INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
	VALUES($1,$2,$3,'encrypt',$4);", &[
		&new_entry.get_field("Timestamp")?,
		&keys["encryption.public"].as_str(),
		&keys["encryption.private"].as_str(),
		&get_hash("BLAKE3-256", &keys["encryption.public"].as_bytes())?.to_string(),
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding updated encryption keys to orgkeys table: {}", e.to_string())
			))
		}
	}

	match db.execute("INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
	VALUES($1,$2,$3,'sign',$4);", &[
		&new_entry.get_field("Timestamp")?,
		&keys["primary.public"].as_str(),
		&keys["primary.private"].as_str(),
		&get_hash("BLAKE3-256", &keys["primary.public"].as_bytes())?.to_string(),
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding updated signing keys to orgkeys table: {}", e.to_string())
			))
		}
	}

	let root_entry = &orgcard.entries[0];
	match db.execute("INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
	VALUES($1,$2,$3,'altsign',$4);", &[
		&root_entry.get_field("Timestamp")?,
		&initial_ospair.get_public_str(),
		&initial_ospair.get_private_str(),
		&get_hash("BLAKE3-256", &initial_ospair.get_public_bytes())?.to_string(),
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding secondary signing keys to orgkeys table: {}", e.to_string())
			))
		}
	}

	// Preregister the admin account

	let admin_wid = RandomID::from("ae406c5e-2673-4d3e-af20-91325d9623ca").unwrap();
	let admin_address = String::from("ae406c5e-2673-4d3e-af20-91325d9623ca/example.com");
	let regcode = "Undamaged Shining Amaretto Improve Scuttle Uptake";
	match db.execute("INSERT INTO prereg(wid,uid,domain,regcode) 
	VALUES($1,'admin','example.com',$2);", &[
		&admin_wid.to_string(),
		&regcode,
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error preregistering admin account: {}", e.to_string())
			))
		}
	}

	// Set up abuse/support forwarding to admin

	let abuse_wid = RandomID::from("f8cfdbdf-62fe-4275-b490-736f5fdc82e3").unwrap();
	match db.execute("INSERT INTO workspaces(wid, uid, domain, password, status, wtype) 
	VALUES($1,'abuse','example.com', '-', 'active', 'alias');", &[&abuse_wid.to_string()]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding abuse account to workspace table: {}", e.to_string())
			))
		}
	}
	match db.execute("INSERT INTO aliases(wid, alias) VALUES($1,$2);", &[
		&abuse_wid.to_string(),
		&admin_address,
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding abuse account to alias table: {}", e.to_string())
			))
		}
	}

	let support_wid = RandomID::from("f0309ef1-a155-4655-836f-55173cc1bc3b").unwrap();
	match db.execute("INSERT INTO workspaces(wid, uid, domain, password, status, wtype) 
	VALUES($1,'support','example.com', '-', 'active', 'alias');", &[&support_wid.to_string()]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding support account to workspace table: {}", e.to_string())
			))
		}
	}
	match db.execute("INSERT INTO aliases(wid, alias) VALUES($1,$2);", &[
		&support_wid.to_string(),
		&admin_address,
	]) {
		Ok(_) => (),
		Err(e) => {
			return Err(MensagoError::ErrProgramException(
				format!("error adding support account to alias table: {}", e.to_string())
			))
		}
	}

	let mut out = HashMap::<&'static str, String>::new();
	out.insert("ovkey", keys["primary.public"].to_string());
	out.insert("oskey", keys["primary.private"].to_string());
	out.insert("oekey", keys["encryption.public"].to_string());
	out.insert("odkey", keys["encryption.private"].to_string());
	out.insert("admin_wid", admin_wid.to_string());
	out.insert("admin_regcode", String::from(regcode));
	out.insert("abuse_wid", abuse_wid.to_string());
	out.insert("support_wid", support_wid.to_string());

	Ok(out)
}

/// Resets the system workspace storage directory to an empty skeleton
pub fn reset_workspace_dir(config: &Document) -> Result<(), MensagoError> {

	let workstr = config["global"]["workspace_dir"].as_str().unwrap();
	let mut globpath = PathBuf::from(&workstr);
	globpath.push("*");

	// Delete all contents of the workspace directory
	// for item in glob::glob(path.to_str().unwrap()).unwrap() {
	for item in glob::glob(globpath.to_str().unwrap()).unwrap() {
		let entry = match item {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("couldn't read entry: {}", e.to_string())
				))
			}
		};

		// Because *NIX filename standards are stupid. *grrr*
		match entry.to_str() {
			Some(_) => (),
			None => {
				return Err(MensagoError::ErrProgramException(
					format!("filesystem entry with non-UTF8 name like {}. Please resolve this.",
						entry.to_string_lossy())
				))
			}
		}

		if entry.is_file() {
			match fs::remove_file(&entry) {
				Ok(_) => (),
				Err(e) => {
					return Err(MensagoError::ErrProgramException(
						format!("couldn't delete file {}: {}", entry.to_str().unwrap(),
							e.to_string())
					))
				}
			}
		} else if entry.is_dir() {
			match fs::remove_dir_all(&entry) {
				Ok(_) => (),
				Err(e) => {
					return Err(MensagoError::ErrProgramException(
						format!("couldn't delete file {}: {}", entry.to_str().unwrap(),
							e.to_string())
					))
				}
			}
		}
	}

	let mut path = PathBuf::from(config["global"]["workspace_dir"].as_str().unwrap());
	path.push("tmp");
	if !path.exists() {
		fs::create_dir(&path)?;
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use libmensago::*;
	use super::*;

	#[test]
	fn test_load_server_config() -> Result<(), MensagoError> {
		
		let config = load_server_config(true)?;

		println!("{:#?}", config);

		println!("max_failures: {}", config["security"].get("max_failures").unwrap()
			.as_integer().unwrap());
		Ok(())
	}

	#[test]
	fn test_setup_test() -> Result<(), MensagoError> {
		
		let config = load_server_config(true)?;
		setup_test(&config)?;

		Ok(())
	}

	#[test]
	fn test_init_server() -> Result<(), MensagoError> {
		
		let config = load_server_config(true)?;
		let mut db = setup_test(&config)?;
		init_server(&mut db)?;

		Ok(())
	}

	#[test]
	fn test_reset_workspace_dir() -> Result<(), MensagoError> {
		
		let config = load_server_config(true)?;
		reset_workspace_dir(&config)?;

		Ok(())
	}
}

// TODO: finish porting integration test setup code from pymensago

// TODO: write setup code tests

