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
use lazy_static::lazy_static;
use libkeycard::*;
use libmensago::*;
use postgres::{Client, NoTls};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{env, fs, path::PathBuf, str::FromStr};
use std::{thread, time};
use toml_edit::{value, Document};
use trust_dns_resolver::config::*;

lazy_static! {

    // WARNING! WARNING! DANGER WILL ROBINSON!
    // THIS INFORMATION IS STORED IN GITLAB! DO NOT USE FOR ANYTHING EXCEPT INTEGRATION TESTS!

    // Test Organization Information

    // Name: Example.com
    // Contact-Admin: ae406c5e-2673-4d3e-af20-91325d9623ca/acme.com
    // Support and Abuse accounts are forwarded to Admin
    // Language: en

    // Initial Organization Primary Signing Key: {UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_
    // Initial Organization Primary Verification Key: r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*
    // Initial Organization Primary Verification Key Hash:
    // 	BLAKE2B-256:ag29av@TUvh-V5KaB2l}H=m?|w`}dvkS1S1&{cMo

    // Initial Organization Encryption Key: SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az
    // Initial Organization Encryption Key Hash: BLAKE2B-256:-Zz4O7J;m#-rB)2llQ*xTHjtblwm&kruUVa_v(&W
    // Initial Organization Decryption Key: WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o

    // Test profile data for the administrator account used in integration tests
    pub static ref ADMIN_PROFILE_DATA: HashMap<&'static str, String> = {
        let mut m = HashMap::new();
        m.insert("name", String::from("Administrator"));
        m.insert("uid", String::from("admin"));
        m.insert("wid", String::from("ae406c5e-2673-4d3e-af20-91325d9623ca"));
        m.insert("domain", String::from("example.com"));
        m.insert("address", String::from("admin/example.com"));
        m.insert("waddress", String::from("ae406c5e-2673-4d3e-af20-91325d9623ca/example.com"));
        m.insert("password", String::from("Linguini2Pegboard*Album"));
        m.insert("passhash", String::from("$argon2id$v=19$m=65536,t=2,p=1$anXvadxtNJAYa2cUQ\
        FqKSQ$zLbLnmbtluKQIOKHk0Hb7+kQZHmZG4Uxf3DI7soKiYE"));
        m.insert("crencryption.public",
            String::from("CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^$iiN{5R->#jxO@cy6{"));
        m.insert("crencryption.private",
            String::from("CURVE25519:2bLf2vMA?GA2?L~tv<PA9XOw6e}V~ObNi7C&qek>"));
        m.insert("crsigning.public",
            String::from("ED25519:E?_z~5@+tkQz!iXK?oV<Zx(ec;=27C8Pjm((kRc|"));
        m.insert("crsigning.private",
            String::from("ED25519:u4#h6LEwM6Aa+f<++?lma4Iy63^}V$JOP~ejYkB;"));
        m.insert("encryption.public",
            String::from("CURVE25519:Umbw0Y<^cf1DN|>X38HCZO@Je(zSe6crC6X_C_0F"));
        m.insert("encryption.private",
            String::from("CURVE25519:Bw`F@ITv#sE)2NnngXWm7RQkxg{TYhZQbebcF5b$"));
        m.insert("signing.public",
            String::from("ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p"));
        m.insert("signing.private",
            String::from("ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+"));
        m.insert("storage",
            String::from("XSALSA20:M^z-E(u3QFiM<QikL|7|vC|aUdrWI6VhN+jt>GH}"));
        m.insert("folder",
            String::from("XSALSA20:H)3FOR}+C8(4Jm#$d+fcOXzK=Z7W+ZVX11jI7qh*"));
        m.insert("device.public",
            String::from("CURVE25519:mO?WWA-k2B2O|Z%fA`~s3^$iiN{5R->#jxO@cy6{"));
        m.insert("device.private",
            String::from("CURVE25519:2bLf2vMA?GA2?L~tv<PA9XOw6e}V~ObNi7C&qek>"));
        m.insert("devid",
            String::from("3abaa743-40d9-4897-ac77-6a7783083f30"));
        m
    };

    // Test profile data for the test user account used in integration tests
    pub static ref USER1_PROFILE_DATA: HashMap<&'static str, String> = {
        let mut m = HashMap::new();
        m.insert("name", String::from("Corbin Simons"));
        m.insert("uid", String::from("csimons"));
        m.insert("wid", String::from("4418bf6c-000b-4bb3-8111-316e72030468"));
        m.insert("domain", String::from("example.com"));
        m.insert("address", String::from("csimons/example.com"));
        m.insert("waddress", String::from("4418bf6c-000b-4bb3-8111-316e72030468/example.com"));
        m.insert("password", String::from("MyS3cretPassw*rd"));
        m.insert("passhash", String::from("$argon2id$v=19$m=65536,t=2,p=1$ejzAtaom5H1y6wnLH\
        vrb7g$ArzyFkg5KH5rp8fa6/7iLp/kAVLh9kaSJQfUKMnHWRM"));
        m.insert("crencryption.public",
            String::from("CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph"));
        m.insert("crencryption.private",
            String::from("CURVE25519:55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}"));
        m.insert("crsigning.public",
            String::from("ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D"));
        m.insert("crsigning.private",
            String::from("ED25519:ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9"));
        m.insert("encryption.public",
            String::from("CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN"));
        m.insert("encryption.private",
            String::from("CURVE25519:4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg"));
        m.insert("signing.public",
            String::from("ED25519:k^GNIJbl3p@N=j8diO-wkNLuLcNF6#JF=@|a}wFE"));
        m.insert("signing.private",
            String::from("ED25519:;NEoR>t9n3v%RbLJC#*%n4g%oxqzs)&~k+fH4uqi"));
        m.insert("storage",
            String::from("XSALSA20:(bk%y@WBo3&}(UeXeHeHQ|1B}!rqYF20DiDG+9^Q"));
        m.insert("folder",
            String::from("XSALSA20:-DfH*_9^tVtb(z9j3Lu@_(=ow7q~8pq^<;;f%2_B"));
        m.insert("device.public",
            String::from("CURVE25519:94|@e{Kpsu_Qe{L@_U;QnOHz!eJ5zz?V@>+K)6F}"));
        m.insert("device.private",
            String::from("CURVE25519:!x2~_pSSCx1M$n7{QBQ5e*%~ytBzKL_C(bCviqYh"));
        m.insert("devid",
            String::from("fd21b07b-6112-4a89-b998-a1c55755d9d7"));
        m
    };
}

/// Returns the canonical version of the path specified.
pub fn get_path_for_test(name: &str) -> Option<String> {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path.push("testfiles");
    path.push(name);

    match path.to_str() {
        Some(v) => Some(String::from(v)),
        None => None,
    }
}

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
                return Err(MensagoError::ErrProgramException(format!(
                    "error parsing server config file: {}",
                    e.to_string()
                )))
            }
        };
    } else {
        return Err(MensagoError::ErrProgramException(String::from(
            "server config file not found",
        )));
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
        (
            "global",
            "registration_subnet",
            "192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.1/8",
        ),
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
        .as_str()
        .unwrap()
        .replace(r#"\"#, r#"\\"#)
        .replace("'", r#"\'"#);

    let mut db = match Client::connect(
        &format!(
            "host='{}' port='{}' dbname='{}' user='{}' password='{}'",
            config["database"]["ip"].as_str().unwrap(),
            config["database"]["port"].as_str().unwrap(),
            config["database"]["name"].as_str().unwrap(),
            config["database"]["user"].as_str().unwrap(),
            password
        ),
        NoTls,
    ) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "couldn't connect to postgres database: {}",
                e.to_string()
            )))
        }
    };

    match db.batch_execute(
        "
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
	",
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error resetting postgres database: {}",
                e.to_string()
            )))
        }
    }

    Ok(db)
}

// Adds basic data to the database as if setup had been run. It also rotates the org
// keycard so that there are two entries. Returns data needed for tests, such as the keys
pub fn init_server(
    db: &mut postgres::Client,
) -> Result<HashMap<&'static str, String>, MensagoError> {
    // Start off by generating the org's root keycard entry and add to the database
    let mut orgcard = Keycard::new(EntryType::Organization);
    let mut root_entry = Entry::new(EntryType::Organization)?;
    root_entry.set_fields(&vec![
        (String::from("Index"), String::from("1")),
        (String::from("Name"), String::from("Example, Inc.")),
        (
            String::from("Contact-Admin"),
            String::from("c590b44c-798d-4055-8d72-725a7942f3f6/example.com"),
        ),
        (String::from("Language"), String::from("en")),
        (String::from("Domain"), String::from("example.com")),
        (
            String::from("Primary-Verification-Key"),
            String::from("ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*"),
        ),
        (
            String::from("Encryption-Key"),
            String::from("CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"),
        ),
    ])?;

    let initial_ospair = SigningPair::from(
        &CryptoString::from("ED25519:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*").unwrap(),
        &CryptoString::from("ED25519:{UNQmjYhz<(-ikOBYoEQpXPt<irxUF*nq25PoW=_").unwrap(),
    )
    .unwrap();
    let initial_oepair = EncryptionPair::from(
        &CryptoString::from("CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az").unwrap(),
        &CryptoString::from("CURVE25519:WSHgOhi+bg=<bO^4UoJGF-z9`+TBN{ds?7RZ;w3o").unwrap(),
    )
    .unwrap();

    match root_entry.is_data_compliant() {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "root org entry not data compliant: {}",
                e.to_string()
            )))
        }
    }

    match root_entry.hash("BLAKE3-256") {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "couldn't hash root org entry: {}",
                e.to_string()
            )))
        }
    }

    match root_entry.sign("Organization-Signature", &initial_ospair) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "failed to sign root org entry: {}",
                e.to_string()
            )))
        }
    }

    match root_entry.verify_signature("Organization-Signature", &initial_ospair) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "couldn't verify root org entry: {}",
                e.to_string()
            )))
        }
    }

    match root_entry.is_compliant() {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "root org entry not compliant: {}",
                e.to_string()
            )))
        }
    }

    orgcard.entries.push(root_entry);

    {
        // Limit scope for access to root entry to enable chaining later

        let root_entry = &orgcard.entries[0];
        let index = match root_entry.get_field("Index")?.parse::<i32>() {
            Ok(v) => v,
            Err(e) => panic!("{}", e.to_string()),
        };
        match db.execute(
            "INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) 
		VALUES('organization',$1,$2,$3,$4);",
            &[
                &root_entry.get_field("Timestamp")?,
                &index,
                &root_entry.get_full_text("")?,
                &root_entry.get_authstr("Hash")?.to_string(),
            ],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "error initializing keycard table: {}",
                    e.to_string()
                )))
            }
        }

        match db.execute(
            "INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
		VALUES($1,$2,$3,'encrypt',$4);",
            &[
                &root_entry.get_field("Timestamp")?,
                &initial_oepair.get_public_str(),
                &initial_oepair.get_private_str(),
                &get_hash("BLAKE3-256", &initial_oepair.get_public_bytes())?.to_string(),
            ],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "error adding encryption keys to orgkeys table: {}",
                    e.to_string()
                )))
            }
        }

        match db.execute(
            "INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
		VALUES($1,$2,$3,'sign',$4);",
            &[
                &root_entry.get_field("Timestamp")?,
                &initial_ospair.get_public_str(),
                &initial_ospair.get_private_str(),
                &get_hash("BLAKE3-256", &initial_ospair.get_public_bytes())?.to_string(),
            ],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "error adding signing keys to orgkeys table: {}",
                    e.to_string()
                )))
            }
        }
    }

    // Chain new entry to the root and add to the database

    let keys = match orgcard.chain(&initial_ospair, 365) {
        Ok(v) => (v),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error chaining org root entry: {}",
                e.to_string()
            )))
        }
    };

    let new_entry = &orgcard.entries[1];
    let index = match new_entry.get_field("Index")?.parse::<i32>() {
        Ok(v) => v,
        Err(e) => panic!("{}", e.to_string()),
    };
    match db.execute(
        "INSERT INTO keycards(owner,creationtime,index,entry,fingerprint) 
	VALUES('organization',$1,$2,$3,$4);",
        &[
            &new_entry.get_field("Timestamp")?,
            &index,
            &new_entry.get_full_text("")?,
            &new_entry.get_authstr("Hash")?.to_string(),
        ],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding updated entry to keycard table: {}",
                e.to_string()
            )))
        }
    }

    match db.execute(
        "UPDATE orgkeys SET creationtime=$1,pubkey=$2,privkey=$3,fingerprint=$4 
	WHERE purpose='encrypt';",
        &[
            &new_entry.get_field("Timestamp")?,
            &keys["encryption.public"].as_str(),
            &keys["encryption.private"].as_str(),
            &get_hash("BLAKE3-256", &keys["encryption.public"].as_bytes())?.to_string(),
        ],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding updated encryption keys to orgkeys table: {}",
                e.to_string()
            )))
        }
    }

    match db.execute(
        "UPDATE orgkeys SET creationtime=$1,pubkey=$2,privkey=$3,fingerprint=$4 
	WHERE purpose='sign';",
        &[
            &new_entry.get_field("Timestamp")?,
            &keys["primary.public"].as_str(),
            &keys["primary.private"].as_str(),
            &get_hash("BLAKE3-256", &keys["primary.public"].as_bytes())?.to_string(),
        ],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding updated signing keys to orgkeys table: {}",
                e.to_string()
            )))
        }
    }

    let root_entry = &orgcard.entries[0];
    match db.execute(
        "INSERT INTO orgkeys(creationtime,pubkey,privkey,purpose,fingerprint) 
	VALUES($1,$2,$3,'altsign',$4);",
        &[
            &root_entry.get_field("Timestamp")?,
            &initial_ospair.get_public_str(),
            &initial_ospair.get_private_str(),
            &get_hash("BLAKE3-256", &initial_ospair.get_public_bytes())?.to_string(),
        ],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding secondary signing keys to orgkeys table: {}",
                e.to_string()
            )))
        }
    }

    // Preregister the admin account

    let admin_wid = RandomID::from(ADMIN_PROFILE_DATA.get("wid").unwrap()).unwrap();
    let regcode = "Undamaged Shining Amaretto Improve Scuttle Uptake";
    match db.execute(
        "INSERT INTO prereg(wid,uid,domain,regcode) 
	VALUES($1,'admin','example.com',$2);",
        &[&admin_wid.to_string(), &regcode],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error preregistering admin account: {}",
                e.to_string()
            )))
        }
    }

    // Set up abuse/support forwarding to admin

    let abuse_wid = RandomID::from("f8cfdbdf-62fe-4275-b490-736f5fdc82e3").unwrap();
    match db.execute(
        "INSERT INTO workspaces(wid, uid, domain, password, status, wtype) 
	VALUES($1,'abuse','example.com', '-', 'active', 'alias');",
        &[&abuse_wid.to_string()],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding abuse account to workspace table: {}",
                e.to_string()
            )))
        }
    }
    match db.execute(
        "INSERT INTO aliases(wid, alias) VALUES($1,$2);",
        &[
            &abuse_wid.to_string(),
            &ADMIN_PROFILE_DATA.get("address").unwrap(),
        ],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding abuse account to alias table: {}",
                e.to_string()
            )))
        }
    }

    let support_wid = RandomID::from("f0309ef1-a155-4655-836f-55173cc1bc3b").unwrap();
    match db.execute(
        "INSERT INTO workspaces(wid, uid, domain, password, status, wtype) 
	VALUES($1,'support','example.com', '-', 'active', 'alias');",
        &[&support_wid.to_string()],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding support account to workspace table: {}",
                e.to_string()
            )))
        }
    }
    match db.execute(
        "INSERT INTO aliases(wid, alias) VALUES($1,$2);",
        &[
            &support_wid.to_string(),
            &ADMIN_PROFILE_DATA.get("address").unwrap(),
        ],
    ) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "error adding support account to alias table: {}",
                e.to_string()
            )))
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
                return Err(MensagoError::ErrProgramException(format!(
                    "couldn't read entry: {}",
                    e.to_string()
                )))
            }
        };

        // Because *NIX filename standards are stupid. *grrr*
        match entry.to_str() {
            Some(_) => (),
            None => {
                return Err(MensagoError::ErrProgramException(format!(
                    "filesystem entry with non-UTF8 name like {}. Please resolve this.",
                    entry.to_string_lossy()
                )))
            }
        }

        if entry.is_file() {
            match fs::remove_file(&entry) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "couldn't delete file {}: {}",
                        entry.to_str().unwrap(),
                        e.to_string()
                    )))
                }
            }
        } else if entry.is_dir() {
            match fs::remove_dir_all(&entry) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "couldn't delete file {}: {}",
                        entry.to_str().unwrap(),
                        e.to_string()
                    )))
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

/// Creates a new profile folder hierarchy on the client side in the specified test folder
pub fn setup_profile_base(name: &str) -> Result<String, MensagoError> {
    let testpath = PathBuf::from(get_path_for_test(name).unwrap());

    if testpath.exists() {
        while testpath.exists() {
            match fs::remove_dir_all(&testpath) {
                Ok(_) => break,
                Err(_) => {
                    println!("Waiting a second for test folder to unlock");
                    thread::sleep(time::Duration::from_secs(1));
                }
            }
        }
        fs::create_dir(&testpath)?;
    } else {
        fs::create_dir_all(&testpath)?;
    }

    match testpath.to_str() {
        Some(v) => return Ok(String::from(v)),
        None => {
            return Err(MensagoError::ErrProgramException(format!(
                "filesystem entry with non-UTF8 name like {}. Please resolve this.",
                testpath.to_string_lossy()
            )))
        }
    }
}

// Profile_data fields
// Note that the field names are carefully chosen -- for code efficiency they are the exact same
// field names as those used in the database to identify the key types. All items are strings and
// will need to be instantiated to their proper types when needed.

// name - (str) the user's name
// uid - (UserID) user ID of the user
// wid - (RandomID) workspace ID of the user
// domain - (Domain) domain of the user
// address - (MAddress) full address of the user -- exists just for convenience
// password - (Password) password object of the user's password
// device.(public|private) - (EncryptionPair) first device encryption pair
// crencryption.(public|private) - (EncryptionPair) contact request encryption pair
// crsigning.(public|private) - (SigningPair) contact request signing pair
// encryption.(public|private) - (EncryptionPair) general encryption pair
// signing.(public|private) - (SigningPair) general signing pair
// folder - (SecretKey) secret key for server-side folder name storage
// storage - (SecretKey) secret key for server-side file storage
pub fn setup_profile(
    profile_folder: &str,
    config: &mut Document,
    profile_data: &HashMap<&'static str, String>,
) -> Result<ArgonHash, MensagoError> {
    config["profile_folder"] = value(profile_folder);

    let pbuf = match PathBuf::from_str(profile_folder) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "bad path in setup_profile: {}",
                e.to_string()
            )))
        }
    };

    let mut profman = libmensago::ProfileManager::new(&pbuf);
    profman.load_profiles(Some(&pbuf))?;
    let profile = match profman.get_active_profile_mut() {
        Some(v) => v,
        None => {
            return Err(MensagoError::ErrProgramException(format!(
                "failed to get active profile from profile manager"
            )))
        }
    };

    // The profile folder is assumed to be empty for the purposes of these tests. 'primary' is
    // assigned to the admin. Test users are assigned 'user1' and 'user2' for clarity.

    let mut w = Workspace::new(&profile.path);
    w.generate(
        Some(&UserID::from(&profile_data.get("uid").as_ref().unwrap()).unwrap()),
        &Domain::from(&profile_data.get("domain").as_ref().unwrap()).unwrap(),
        &RandomID::from(&profile_data.get("wid").as_ref().unwrap()).unwrap(),
        &profile_data.get("passhash").as_ref().unwrap(),
    )?;

    let password = ArgonHash::from_hashstr(&profile_data.get("passhash").as_ref().unwrap());
    profile.set_identity(w, &password)?;

    Ok(password)
}

/// Performs a login sequence
pub fn login_user<K: Encryptor>(
    conn: &mut ServerConnection,
    wid: &RandomID,
    oekey: &K,
    pwhash: &ArgonHash,
    devid: &RandomID,
    devpair: &EncryptionPair,
) -> Result<(), MensagoError> {
    match login(conn, wid, oekey) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "login() failed in login_user: {}",
                e.to_string()
            )))
        }
    }

    match password(conn, &pwhash) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "password() failed in login_user: {}",
                e.to_string()
            )))
        }
    }

    match device(conn, &devid, &devpair) {
        Ok(v) => {
            if !v {
                return Err(MensagoError::ErrProgramException(format!(
                    "device() failed in login_user"
                )));
            }
        }
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "device() error in login_user: {}",
                e.to_string()
            )))
        }
    }

    Ok(())
}

/// Finishes setting up a user account by registering it, logging in, and uploading a root
/// keycard entry.
pub fn regcode_user(
    conn: &mut ServerConnection,
    profman: &mut ProfileManager,
    dbdata: &HashMap<&'static str, String>,
    profile_data: &HashMap<&'static str, String>,
    user_regcode: &str,
    pwhash: &ArgonHash,
) -> Result<HashMap<&'static str, String>, MensagoError> {
    let profile = profman.get_active_profile().unwrap();

    let devid = RandomID::from(&profile_data["devid"]).unwrap();
    let mut regdata = match regcode(
        conn,
        MAddress::from(&profile_data["address"]).as_ref().unwrap(),
        user_regcode,
        pwhash,
        &devid,
        &CryptoString::from(&profile_data["device.public"]).unwrap(),
    ) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "regcode failed in regcode_user: {}",
                e.to_string()
            )))
        }
    };
    regdata.insert("devid", devid.to_string());

    let waddr = WAddress::from(&ADMIN_PROFILE_DATA["waddress"]).unwrap();
    let devpair = EncryptionPair::from_strings(
        &ADMIN_PROFILE_DATA["device.public"],
        &ADMIN_PROFILE_DATA["device.private"],
    )
    .unwrap();
    let db = profile.open_secrets()?;
    match add_device_session(&db, &waddr, &devid, &devpair, None) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "add_device_session() failed in regcode_user: {}",
                e.to_string()
            )))
        }
    }

    let oekey = EncryptionKey::from_string(&dbdata["oekey"]).unwrap();
    match login_user(conn, waddr.get_wid(), &oekey, &pwhash, &devid, &devpair) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "login_user() failed in regcode_user: {}",
                e.to_string()
            )))
        }
    }

    // Admin login complete. Now create and upload the admin account's root keycard entry

    let mut entry = Entry::new(EntryType::User).unwrap();
    entry.set_fields(&vec![
        (String::from("Index"), String::from("1")),
        (String::from("Name"), profile_data["name"].clone()),
        (String::from("Workspace-ID"), profile_data["wid"].clone()),
        (String::from("User-ID"), profile_data["uid"].clone()),
        (String::from("Domain"), profile_data["domain"].clone()),
        (
            String::from("Contact-Request-Verification-Key"),
            profile_data["crsigning.public"].clone(),
        ),
        (
            String::from("Contact-Request-Encryption-Key"),
            profile_data["crencryption.public"].clone(),
        ),
        (
            String::from("Encryption-Key"),
            profile_data["encryption.public"].clone(),
        ),
        (
            String::from("Verification-Key"),
            profile_data["signing.public"].clone(),
        ),
    ])?;

    let ovkey = VerificationKey::from_string(&dbdata["ovkey"]).unwrap();
    let crspair = SigningPair::from_strings(
        &profile_data["crsigning.public"],
        &profile_data["crsigning.private"],
    )?;
    match addentry(conn, &mut entry, &ovkey, &crspair) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "addentry() failed in regcode_user: {}",
                e.to_string()
            )))
        }
    }

    match iscurrent(conn, 1, profile.wid.as_ref()) {
        Ok(v) => {
            if !v {
                return Err(MensagoError::ErrProgramException(format!(
                    "iscurrent() returned false in regcode_user"
                )));
            }
        }
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "iscurrent() failed in regcode_user: {}",
                e.to_string()
            )))
        }
    }

    // Add the user's keycard to the database

    let mut admincard = Keycard::new(EntryType::User);
    admincard.entries.push(entry);

    let dbconn = match profile.open_storage() {
        Ok(v) => (v),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "regcode_user: couldn't open db: {}",
                e.to_string()
            )))
        }
    };

    match update_keycard_in_db(&dbconn, &admincard, false) {
        Ok(v) => (v),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "regcode_user: update_keycard_in_db error: {}",
                e.to_string()
            )))
        }
    }

    Ok(regdata)
}

/// Completely sets up a test by:
///
/// - Loading the server config file (load_server_config)
/// - Empties and resets the server's database (setup_test)
/// - Adds basic test data as if setup had been run  (init_server)
/// - Sets up a new test profile folder hierarchy (setup_profile_base)
/// - Creates a profile for the administrator via setup_profile()
/// - Loads and initializes a ProfileManager instance
/// - Creates a network connection to the server via ServerConnection
/// - Registers the administrator account (regcode_user)
///
/// Once all this has been accomplished, it returns the commonly-used output of each of the calls
/// so that the test has complete context for its actions
pub fn full_test_setup(
    testname: &str,
) -> Result<
    (
        Document,
        Client,
        HashMap<&'static str, String>,
        String,
        ArgonHash,
        ProfileManager,
        ServerConnection,
        HashMap<&'static str, String>,
    ),
    MensagoError,
> {
    let mut config = load_server_config(true)?;
    let mut db = match setup_test(&config) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: setup_test error: {}",
                testname,
                e.to_string()
            )))
        }
    };
    let dbdata = match init_server(&mut db) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: init_server error: {}",
                testname,
                e.to_string()
            )))
        }
    };
    let profile_folder = match setup_profile_base(testname) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: setup_profile_base error: {}",
                testname,
                e.to_string()
            )))
        }
    };
    let pwhash = match setup_profile(&profile_folder, &mut config, &ADMIN_PROFILE_DATA) {
        Ok(v) => v,
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: setup_profile error: {}",
                testname,
                e.to_string()
            )))
        }
    };

    let mut profman = ProfileManager::new(&PathBuf::from(&profile_folder));
    match profman.load_profiles(Some(&PathBuf::from(&profile_folder))) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_profiles error: {}",
                testname,
                e.to_string()
            )))
        }
    };

    let mut conn = ServerConnection::new();
    let port = config["network"]["port"].as_integer().unwrap() as u16;
    match conn.connect(config["network"]["listen_ip"].as_str().unwrap(), port) {
        Ok(_) => (),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: error connecting to server: {}",
                testname,
                e.to_string()
            )))
        }
    }

    let admin_regdata = match regcode_user(
        &mut conn,
        &mut profman,
        &dbdata,
        &ADMIN_PROFILE_DATA,
        &dbdata["admin_regcode"],
        &pwhash,
    ) {
        Ok(v) => (v),
        Err(e) => {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: regcode_user error: {}",
                testname,
                e.to_string()
            )))
        }
    };

    Ok((
        config,
        db,
        dbdata,
        profile_folder,
        pwhash,
        profman,
        conn,
        admin_regdata,
    ))
}

/// The FakeDNSHandler type provides mock DNS information for unit testing purposes
pub struct FakeDNSHandler {
    error_list: VecDeque<FakeDNSError>,
    db_str: String,
}

impl FakeDNSHandler {
    pub fn new() -> FakeDNSHandler {
        // We need to be able to connect to the
        let config = match load_server_config(true) {
            Ok(v) => v,
            Err(e) => panic!("{}", e.to_string()),
        };

        // postgres::connect requires escaping backslashes and single quotes.
        let password = config["database"]["password"]
            .as_str()
            .unwrap()
            .replace(r#"\"#, r#"\\"#)
            .replace("'", r#"\'"#);

        FakeDNSHandler {
            error_list: VecDeque::new(),
            db_str: format!(
                "host='{}' port='{}' dbname='{}' user='{}' password='{}'",
                config["database"]["ip"].as_str().unwrap(),
                config["database"]["port"].as_str().unwrap(),
                config["database"]["name"].as_str().unwrap(),
                config["database"]["user"].as_str().unwrap(),
                password
            ),
        }
    }

    pub fn push_error(&mut self, e: FakeDNSError) {
        self.error_list.push_back(e)
    }
}

impl DNSHandlerT for FakeDNSHandler {
    /// Normally sets the server and configuration information. This call for FakeDNSHandler is
    /// a no-op
    fn set_server(
        &mut self,
        _config: ResolverConfig,
        _opts: ResolverOpts,
    ) -> Result<(), MensagoError> {
        Ok(())
    }

    /// Normally turns a DNS domain into an IPv4 address. This implementation always returns
    /// 127.0.0.1.
    fn lookup_a(&mut self, _d: &Domain) -> Result<IpAddr, MensagoError> {
        match self.error_list.pop_front() {
            Some(e) => match e {
                FakeDNSError::NoResponse => return Err(MensagoError::ErrNetworkError),
                FakeDNSError::Misconfig => return Ok(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                FakeDNSError::Empty => return Err(MensagoError::ErrEmptyData),
                FakeDNSError::NotFound => return Err(MensagoError::ErrNotFound),
            },
            None => (),
        }

        Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    /// Normally turns a DNS domain into an IPv6 address. This implementation always returns
    /// ::1.
    fn lookup_aaaa(&mut self, _d: &Domain) -> Result<IpAddr, MensagoError> {
        match self.error_list.pop_front() {
            Some(e) => match e {
                FakeDNSError::NoResponse => return Err(MensagoError::ErrNetworkError),
                FakeDNSError::Misconfig => {
                    return Ok(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)))
                }
                FakeDNSError::Empty => return Err(MensagoError::ErrEmptyData),
                FakeDNSError::NotFound => return Err(MensagoError::ErrNotFound),
            },
            None => (),
        }

        Ok(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
    }

    /// Normally returns all service records for a domain. This implementation always returns
    /// mensago.example.com on port 2001 with a TTL of 86400.
    fn lookup_srv(&mut self, _d: &str) -> Result<Vec<ServiceConfigRecord>, MensagoError> {
        match self.error_list.pop_front() {
            Some(e) => match e {
                FakeDNSError::NoResponse => return Err(MensagoError::ErrNetworkError),
                FakeDNSError::Empty => return Err(MensagoError::ErrEmptyData),
                FakeDNSError::NotFound => return Err(MensagoError::ErrNotFound),
                FakeDNSError::Misconfig => {
                    return Ok(vec![ServiceConfigRecord {
                        server: Domain::from("myhostname").unwrap(),
                        port: 0,
                        priority: 100,
                    }])
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
            Some(e) => match e {
                FakeDNSError::NoResponse => return Err(MensagoError::ErrNetworkError),
                FakeDNSError::Empty => return Err(MensagoError::ErrEmptyData),
                FakeDNSError::NotFound => return Err(MensagoError::ErrNotFound),
                FakeDNSError::Misconfig => {
                    return Ok(vec![
                        String::from("pvk=K12:r#r*RiXIN-0n)BzP3bv`LA&t4LFEQNF0Q@$N~RF*"),
                        String::from("svk=CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"),
                    ])
                }
            },
            None => (),
        }

        let mut db = match Client::connect(&self.db_str, NoTls) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "couldn't connect to postgres database: {}",
                    e.to_string()
                )))
            }
        };

        let ek = match db.query("SELECT pubkey FROM orgkeys WHERE purpose = 'encrypt'", &[]) {
            Ok(rows) => CryptoString::from(rows[0].get(0)).expect("failed to get ek from postgres"),
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Query error looking for org keys: {}",
                    e.to_string()
                )))
            }
        };

        let pvk = match db.query("SELECT pubkey FROM orgkeys WHERE purpose = 'sign'", &[]) {
            Ok(rows) => CryptoString::from(rows[0].get(0)).expect("failed to get sk from postgres"),
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Query error looking for org keys: {}",
                    e.to_string()
                )))
            }
        };

        let avk: Option<CryptoString> = match db
            .query("SELECT pubkey FROM orgkeys WHERE purpose = 'altsign'", &[])
        {
            Ok(rows) => Some(CryptoString::from(rows[0].get(0)).expect("bad altsk in postgres")),
            Err(_) => None,
        };

        let mut out = vec![format!("pvk={}", pvk), format!("ek={}", ek)];
        if avk.is_some() {
            out.push(format!("avk={}", avk.unwrap()))
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_server_config() -> Result<(), MensagoError> {
        let config = load_server_config(true)?;

        println!("{:#?}", config);

        println!(
            "max_failures: {}",
            config["security"]
                .get("max_failures")
                .unwrap()
                .as_integer()
                .unwrap()
        );
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

    #[test]
    fn test_setup_profile_base() -> Result<(), MensagoError> {
        setup_profile_base("test_setup_profile_base")?;
        Ok(())
    }

    #[test]
    fn test_setup_profile() -> Result<(), MensagoError> {
        let mut config = load_server_config(true)?;
        let profile_folder = setup_profile_base("test_setup_profile")?;
        setup_profile(&profile_folder, &mut config, &ADMIN_PROFILE_DATA)?;

        Ok(())
    }

    #[test]
    fn test_regcode_user() -> Result<(), MensagoError> {
        let testname = "test_regcode_user";
        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, _, _, _, mut conn, _) = full_test_setup(testname)?;

        conn.disconnect()?;
        Ok(())
    }
}
