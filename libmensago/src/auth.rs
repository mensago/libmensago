// Keys used in the various tests

// THESE KEYS ARE PUBLICLY ACCESSIBLE! DO NOT USE THESE FOR ANYTHING EXCEPT UNIT TESTS!!

// User Verification Key: ED25519:6|HBWrxMY6-?r&Sm)_^PLPerpqOj#b&x#N_#C3}p
// User Signing Key: ED25519:p;XXU0XF#UO^}vKbC-wS(#5W6=OEIFmR2z`rS1j+

// User Contact Request Verification Key: ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D
// User Contact Request Signing Key: ED25519:ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9

// User Contact Request Encryption Key: CURVE25519:j(IBzX*F%OZF;g77O8jrVjM1a`Y<6-ehe{S;{gph
// User Contact Request Decryption Key: CURVE25519:55t6A0y%S?{7c47p(R@C*X#at9Y`q5(Rc#YBS;r}

// User Primary Encryption Key: CURVE25519:nSRso=K(WF{P+4x5S*5?Da-rseY-^>S8VN#v+)IN
// User Primary Decryption Key: CURVE25519:4A!nTPZSVD#tm78d=-?1OIQ43{ipSpE;@il{lYkg

// Session #1 Encryption Key: CURVE25519:^EHgs?Mj1StVPg0&^rOSUeOnLw?g90b+~tplT~aQ
// Session #1 Decryption Key: CURVE25519:9>z?R9M+X%RX&4lMnUEx)~oMV6-{X{^nuhm9v%x<

// Folder Key: XSALSA20:TF_`Q2kZO;nUb(wWm1{P=_BmVe6rEK<GkITq@T|l
// Storage Key: XSALSA20:L_fPZVo1rGPozl^N)bm2$Dc%xyihXmzV}7w^d0xm

// THESE KEYS ARE PUBLICLY ACCESSIBLE! DO NOT USE THESE FOR ANYTHING EXCEPT UNIT TESTS!!

use eznacl::*;
use libkeycard::*;
use rusqlite;
use sys_info;

use crate::base::*;
use crate::types::*;

/// Gets the password hash for the workspace
pub fn get_credentials(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
) -> Result<ArgonHash, MensagoError> {
    let mut stmt = conn.prepare("SELECT password FROM workspaces WHERE wid=?1 AND domain=?2")?;

    let pwstr = stmt.query_row(
        [waddr.get_wid().as_string(), waddr.get_domain().as_string()],
        |row| Ok(row.get::<usize, String>(0).unwrap()),
    )?;

    if pwstr.len() == 0 {
        return Err(MensagoError::ErrNotFound);
    }

    Ok(ArgonHash::from_hashstr(&pwstr))
}

/// Sets the password and hash type for the specified workspace
pub fn set_credentials(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
    pwh: Option<&ArgonHash>,
) -> Result<(), MensagoError> {
    check_workspace_exists(&conn, waddr)?;
    match pwh {
        Some(v) => {
            match conn.execute(
                "UPDATE workspaces SET password=?1,pwhashtype=?2 WHERE wid=?3 AND domain=?4",
                &[
                    v.get_hash(),
                    v.get_hashtype(),
                    waddr.get_wid().as_string(),
                    waddr.get_domain().as_string(),
                ],
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
            }
        }
        None => {
            match conn.execute(
                "UPDATE workspaces SET password='',pwhashtype='' WHERE wid=?1 AND domain=?2",
                &[waddr.get_wid().as_string(), waddr.get_domain().as_string()],
            ) {
                Ok(_) => Ok(()),
                Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
            }
        }
    }
}

/// Adds a device ID to a workspace
pub fn add_device_session(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
    devid: &RandomID,
    devpair: &EncryptionPair,
    devname: Option<&str>,
) -> Result<(), MensagoError> {
    // Can't have a session on that specified server already
    let mut stmt = conn.prepare("SELECT address FROM sessions WHERE address=?1")?;
    match stmt.exists([waddr.as_string()]) {
        Ok(v) => {
            if v {
                return Err(MensagoError::ErrExists);
            }
        }
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    };

    let realname = match devname {
        Some(v) => String::from(v),
        None => make_device_name(),
    };

    match conn.execute(
        "INSERT INTO sessions(address, devid, devname, public_key, private_key, os)
		VALUES(?1,?2,?3,?4,?5,?6)",
        [
            waddr.to_string(),
            devid.to_string(),
            realname,
            devpair.get_public_str(),
            devpair.get_private_str(),
            os_info::get().os_type().to_string().to_lowercase(),
        ],
    ) {
        Ok(_) => Ok(()),
        Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
    }
}

/// Removes an authorized device from the workspace
pub fn remove_device_session(
    conn: &rusqlite::Connection,
    devid: &RandomID,
) -> Result<(), MensagoError> {
    let mut stmt = conn.prepare("SELECT devid FROM sessions WHERE devid=?1")?;
    match stmt.exists([devid.as_string()]) {
        Ok(v) => {
            if !v {
                return Err(MensagoError::ErrNotFound);
            }
        }
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    };

    match conn.execute("DELETE FROM sessions WHERE devid=?1", [devid.as_string()]) {
        Ok(_) => Ok(()),
        Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
    }
}

/// Returns the device key for a server session
pub fn get_session_keypair(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
) -> Result<EncryptionPair, MensagoError> {
    let mut stmt = conn.prepare("SELECT public_key,private_key FROM sessions WHERE address=?1")?;
    let (pubstr, privstr) = stmt.query_row([waddr.as_string()], |row| {
        Ok((
            row.get::<usize, String>(0).unwrap(),
            row.get::<usize, String>(1).unwrap(),
        ))
    })?;

    match EncryptionPair::from_strings(&pubstr, &privstr) {
        Ok(v) => Ok(v),
        Err(e) => Err(MensagoError::EzNaclError(e)),
    }
}

/// Adds a key pair to a workspace.
pub fn add_keypair(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
    pubkey: &CryptoString,
    privkey: &CryptoString,
    hashtype: &str,
    keytype: &KeyType,
    category: &KeyCategory,
) -> Result<CryptoString, MensagoError> {
    conn.execute(
        "DELETE FROM keys WHERE address=?1 AND category=?2",
        [&waddr.to_string(), &category.to_string()],
    )?;

    let pubhash = eznacl::get_hash(hashtype, pubkey.as_bytes())?;

    let timestamp = get_timestamp();

    let type_string = match keytype {
        KeyType::AsymEncryptionKey => "asymmetric",
        KeyType::SigningKey => "signing",

        // add_key() is used for symmetric keys
        KeyType::SymEncryptionKey => return Err(MensagoError::ErrTypeMismatch),
    };

    match conn.execute(
        "INSERT INTO keys(keyid,address,type,category,private,public,timestamp)
	VALUES(?1,?2,?3,?4,?5,?6,?7)",
        [
            pubhash.as_str(),
            &waddr.to_string(),
            type_string,
            &category.to_string(),
            privkey.as_str(),
            pubkey.as_str(),
            &timestamp,
        ],
    ) {
        Ok(_) => Ok(pubhash),
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    }
}

/// Deletes a cryptography keypair from a workspace.
pub fn remove_keypair(
    conn: &rusqlite::Connection,
    keyhash: &CryptoString,
) -> Result<(), MensagoError> {
    remove_key(&conn, &keyhash)
}

/// Returns a pair of CryptoStrings, where the public key is in element 0 and the private key is in
/// element 1. This is to accommodate retrieval of all key types. If a symmetric key is obtained
/// through this call, the public and private key values will be the same.
pub fn get_keypair(
    conn: &rusqlite::Connection,
    keyhash: &CryptoString,
) -> Result<[CryptoString; 2], MensagoError> {
    let mut stmt = conn.prepare("SELECT public,private FROM keys WHERE keyid=?1")?;
    let (pubstr, privstr) = stmt.query_row([keyhash.as_str()], |row| {
        Ok((
            row.get::<usize, String>(0).unwrap(),
            row.get::<usize, String>(1).unwrap(),
        ))
    })?;

    if pubstr.len() == 0 || privstr.len() == 0 {
        return Err(MensagoError::ErrEmptyData);
    }

    let pubcs = CryptoString::from(&pubstr);
    let privcs = CryptoString::from(&privstr);

    if pubcs.is_none() || privcs.is_none() {
        return Err(MensagoError::ErrDatabaseException(String::from(
            "Bad key value in database in get_keypair()",
        )));
    }

    Ok([pubcs.unwrap(), privcs.unwrap()])
}

/// Returns a keypair based on its category
pub fn get_keypair_by_category(
    conn: &rusqlite::Connection,
    category: &KeyCategory,
) -> Result<[CryptoString; 2], MensagoError> {
    let mut stmt = conn.prepare("SELECT public,private FROM keys WHERE category=?1")?;
    let (pubstr, privstr) = stmt.query_row([category.to_string()], |row| {
        Ok((
            row.get::<usize, String>(0).unwrap(),
            row.get::<usize, String>(1).unwrap(),
        ))
    })?;

    if pubstr.len() == 0 || privstr.len() == 0 {
        return Err(MensagoError::ErrEmptyData);
    }

    let pubcs = CryptoString::from(&pubstr);
    let privcs = CryptoString::from(&privstr);

    if pubcs.is_none() || privcs.is_none() {
        return Err(MensagoError::ErrDatabaseException(String::from(
            "Bad key value in database in get_keypair()",
        )));
    }

    Ok([pubcs.unwrap(), privcs.unwrap()])
}

/// Adds a single symmetric key to a workspace. It also creates a hash of the Base85-encoded
/// public key using the requested algorithm and adds it to the database
pub fn add_key(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
    key: &CryptoString,
    hashtype: &str,
    category: &KeyCategory,
) -> Result<CryptoString, MensagoError> {
    let keyhash = eznacl::get_hash(hashtype, key.as_bytes())?;

    conn.execute(
        "DELETE FROM keys WHERE address=?1 AND category=?2",
        [&waddr.to_string(), &category.to_string()],
    )?;

    let timestamp = get_timestamp();

    match conn.execute(
        "INSERT INTO keys(keyid,address,type,category,private,public,timestamp)
		VALUES(?1,?2,?3,?4,?5,?6,?7)",
        [
            keyhash.as_str(),
            &waddr.to_string(),
            "symmetric",
            &category.to_string(),
            key.as_str(),
            key.as_str(),
            &timestamp,
        ],
    ) {
        Ok(_) => return Ok(keyhash),
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    }
}

/// Deletes a cryptography key from a workspace. Note that the algorithm must match, i.e. if a key
/// is stored using a BLAKE2B-256 hash, passing a BLAKE3-256 hash of the exact same key will result
/// in a ErrNotFound error.
pub fn remove_key(conn: &rusqlite::Connection, keyhash: &CryptoString) -> Result<(), MensagoError> {
    let mut stmt = conn.prepare("SELECT keyid FROM keys WHERE keyid=?1")?;
    match stmt.exists([keyhash.as_str()]) {
        Ok(v) => {
            if !v {
                return Err(MensagoError::ErrNotFound);
            }
        }
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    };

    match conn.execute("DELETE FROM keys WHERE keyid=?1)", [keyhash.as_str()]) {
        Ok(_) => return Ok(()),
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    }
}

/// Gets a key given its hash. As with get_keypair(), if the hash given does not use the
/// same algorithm, this function will not find the key.
pub fn get_key(
    conn: &rusqlite::Connection,
    keyhash: &CryptoString,
) -> Result<CryptoString, MensagoError> {
    let mut stmt = conn.prepare("SELECT public FROM keys WHERE keyid=?1")?;
    let pubstr = stmt.query_row([keyhash.to_string()], |row| {
        Ok(row.get::<usize, String>(0).unwrap())
    })?;

    if pubstr.len() == 0 {
        return Err(MensagoError::ErrEmptyData);
    }

    let pubcs = CryptoString::from(&pubstr);

    if pubcs.is_none() {
        return Err(MensagoError::ErrDatabaseException(String::from(
            "Bad key value in database in get_key()",
        )));
    }

    Ok(pubcs.unwrap())
}

/// Returns a key based on its category. If the category given uses a pair of keys, the public key
/// is returned.
pub fn get_key_by_category(
    conn: &rusqlite::Connection,
    category: &KeyCategory,
) -> Result<CryptoString, MensagoError> {
    let mut stmt = conn.prepare("SELECT public FROM keys WHERE category=?1")?;
    let pubstr = stmt.query_row([category.to_string()], |row| {
        Ok(row.get::<usize, String>(0).unwrap())
    })?;

    if pubstr.len() == 0 {
        return Err(MensagoError::ErrEmptyData);
    }

    let pubcs = CryptoString::from(&pubstr);

    if pubcs.is_none() {
        return Err(MensagoError::ErrDatabaseException(String::from(
            "Bad key value in database in get_key_by_category()",
        )));
    }

    Ok(pubcs.unwrap())
}

/// Utility function that just checks to see if a specific workspace exists in the database
fn check_workspace_exists(
    conn: &rusqlite::Connection,
    waddr: &WAddress,
) -> Result<(), MensagoError> {
    let mut stmt = conn.prepare("SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2")?;
    match stmt.exists([waddr.get_wid().as_string(), waddr.get_domain().as_string()]) {
        Ok(v) => {
            if !v {
                return Err(MensagoError::ErrNotFound);
            }
        }
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    };

    Ok(())
}

/// Internal function to construct a device name based on platform and OS
fn make_device_name() -> String {
    let hostname = match sys_info::hostname() {
        Ok(v) => v.to_lowercase(),
        Err(_) => {
            // If we can't get the hostname, we've got bigger problems than just a string name, so
            // just use localhost in that instance.
            String::from("localhost")
        }
    };

    let osname = os_info::get().os_type().to_string().to_lowercase();

    format!("{}-{}", hostname, osname)
}

#[cfg(test)]
mod tests {
    use super::check_workspace_exists;
    use crate::*;
    use eznacl::*;
    use libkeycard::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;

    // Sets up the path to contain the profile tests
    fn setup_test(name: &str) -> PathBuf {
        if name.len() < 1 {
            panic!("Invalid name {} in setup_test", name);
        }
        let args: Vec<String> = env::args().collect();
        let test_path = PathBuf::from_str(&args[0]).unwrap();
        let mut test_path = test_path.parent().unwrap().to_path_buf();
        test_path.push("testfiles");
        test_path.push(name);

        if test_path.exists() {
            fs::remove_dir_all(&test_path).unwrap();
        }
        fs::create_dir_all(&test_path).unwrap();

        test_path
    }

    fn setup_profile(testname: &str, path: &PathBuf) -> Result<ProfileManager, MensagoError> {
        let mut profman = ProfileManager::new(&path);
        let _ = match profman.create_profile("Primary") {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error creating profile 'Primary': {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match profman.activate_profile("Primary") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error activating profile 'Primary': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(profman)
    }

    fn setup_workspace(testname: &str, profpath: &PathBuf) -> Result<Workspace, MensagoError> {
        // Hash of "CheeseCustomerSmugnessDelegatorGenericUnaudited"
        let pw = String::from(
            "$argon2id$v=19$m=1048576,t=1,p=2$jc/H+Cn1NwJBJOTmFqAdlA$\
			b2zoU9ZNhHlo/ZYuSJwoqUAXEdf1cbN3fxmbQhP0zJc",
        );

        let mut w = Workspace::new(profpath);
        match w.generate(
            Some(&UserID::from("csimons").unwrap()),
            Domain::from("example.com").as_ref().unwrap(),
            RandomID::from("b5a9367e-680d-46c0-bb2c-73932a6d4007")
                .as_ref()
                .unwrap(),
            &pw,
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error generating workspace: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let pwhash = ArgonHash::from_hashstr(&pw);
        match w.add_to_db(&pwhash) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding workspace to db: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(w)
    }

    #[test]
    fn get_set_credentials() -> Result<(), MensagoError> {
        let testname = String::from("get_set_credentials");
        let test_path = setup_test(&testname);

        let _ = setup_profile(&testname, &test_path)?;

        let mut profile_path = test_path.clone();
        profile_path.push("primary");
        let w = setup_workspace(&testname, &profile_path)?;

        let conn = match w.open_storage() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to workspace db: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #1: get credentials
        match get_credentials(&conn, &w.get_waddress().unwrap()) {
            Ok(v) => {
                let pwhash = ArgonHash::from_hashstr(
                    "$argon2id$v=19$m=1048576,t=1,p=2\
				$jc/H+Cn1NwJBJOTmFqAdlA$b2zoU9ZNhHlo/ZYuSJwoqUAXEdf1cbN3fxmbQhP0zJc",
                );

                if v != pwhash {
                    println!("Wanted:\n{}-----\nGot:\n{}", pwhash, v);
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: credential mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting credentials: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #2: set credentials

        // Hash of "GloriousBroadlyBackerOverloadBoxcarBrittle"
        let newpw = String::from(
            "$argon2id$v=19$m=1048576,t=1,p=2\
		$46qy9bqnd0CBmq82X01Xjw$+VUx+mkUvFxDE0aum/h6sGA92JeB7CxZolNAoK8iUOY",
        );
        let newhash = ArgonHash::from_hashstr(&newpw);

        match set_credentials(&conn, &w.get_waddress().unwrap(), Some(&newhash)) {
            Ok(_) => {
                match get_credentials(&conn, &w.get_waddress().unwrap()) {
                    Ok(v) => {
                        if v != newhash {
                            println!("Wanted:\n{}-----\nGot:\n{}", newhash, v);
                            return Err(MensagoError::ErrProgramException(format!(
                                "{}: set_credentials value mismatch",
                                testname
                            )));
                        }
                    }
                    Err(e) => {
                        return Err(MensagoError::ErrProgramException(format!(
                            "{}: error getting credentials: {}",
                            testname,
                            e.to_string()
                        )))
                    }
                };
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error setting credentials: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #3: clearing credentials
        match set_credentials(&conn, &w.get_waddress().unwrap(), None) {
            Ok(_) => {
                match get_credentials(&conn, &w.get_waddress().unwrap()) {
                    Ok(_) => {
                        return Err(MensagoError::ErrProgramException(format!(
                            "{}: failed to clear credentials",
                            testname
                        )))
                    }
                    Err(_) => (),
                };
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error setting credentials: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }

    #[test]
    fn add_remove_get_session() -> Result<(), MensagoError> {
        let testname = String::from("add_remove_session");
        let test_path = setup_test(&testname);

        let _ = setup_profile(&testname, &test_path)?;

        let mut profile_path = test_path.clone();
        profile_path.push("primary");
        let w = setup_workspace(&testname, &profile_path)?;

        let conn = match w.open_secrets() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to workspace secrets db: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #1: add session
        let waddr = w.get_waddress().unwrap();
        let devid = RandomID::from("00000000-2222-5555-7777-888888888888").unwrap();
        let devpair = EncryptionPair::from_strings(
            "CURVE25519:^EHgs?Mj1StVPg0&^rOSUeOnLw?g90b+~tplT~aQ",
            "CURVE25519:9>z?R9M+X%RX&4lMnUEx)~oMV6-{X{^nuhm9v%x<",
        )
        .unwrap();
        let devname = String::from("mypc");

        match add_device_session(&conn, &waddr, &devid, &devpair, Some(&devname)) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding device session: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #2: try to add duplicate
        match add_device_session(&conn, &waddr, &devid, &devpair, Some(&devname)) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error failed to catch adding duplicate device session",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #3: get session keypair
        match get_session_keypair(&conn, &waddr) {
            Ok(v) => {
                if v.get_public_str() != devpair.get_public_str()
                    || v.get_private_str() != devpair.get_private_str()
                {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: session keypair mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting session keypair: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #4: remove session keypair
        match remove_device_session(&conn, &devid) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error removing device session: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #5: remove nonexistent keypair
        match remove_device_session(&conn, &devid) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error failed to catch removing nonexistent device session",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #6: get nonexistent keypair
        match get_session_keypair(&conn, &waddr) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error failed to catch getting nonexistent device session",
                    testname
                )))
            }
            Err(_) => (),
        }

        Ok(())
    }

    #[test]
    fn add_remove_get_keypair() -> Result<(), MensagoError> {
        let testname = String::from("add_remove_get_keypair");
        let test_path = setup_test(&testname);

        let _ = setup_profile(&testname, &test_path)?;

        let mut profile_path = test_path.clone();
        profile_path.push("primary");
        let w = setup_workspace(&testname, &profile_path)?;

        let conn = match w.open_secrets() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to workspace secrets db: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let waddr = w.get_waddress().unwrap();
        let crvkey =
            CryptoString::from("ED25519:d0-oQb;{QxwnO{=!|^62+E=UYk2Y3mr2?XKScF4D").unwrap();
        let crskey =
            CryptoString::from("ED25519:ip52{ps^jH)t$k-9bc_RzkegpIW?}FFe~BX&<V}9").unwrap();

        // Case #1: add keypair
        let keyhash = match add_keypair(
            &conn,
            &waddr,
            &crvkey,
            &crskey,
            "blake2b-256",
            &KeyType::SigningKey,
            &KeyCategory::ConReqSigning,
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding CR signing pair: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #2: get keypair
        match get_keypair(&conn, &keyhash) {
            Ok(v) => {
                if v[0] != crvkey || v[1] != crskey {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: get_keypair value mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting CR signing pair: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #3: get keypair by category
        match get_keypair_by_category(&conn, &KeyCategory::ConReqSigning) {
            Ok(v) => {
                if v[0] != crvkey || v[1] != crskey {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: get_keypair value mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting CR signing pair by category: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }

    #[test]
    fn add_remove_get_key() -> Result<(), MensagoError> {
        let testname = String::from("add_remove_get_key");
        let test_path = setup_test(&testname);

        let _ = setup_profile(&testname, &test_path)?;

        let mut profile_path = test_path.clone();
        profile_path.push("primary");
        let w = setup_workspace(&testname, &profile_path)?;

        let conn = match w.open_secrets() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to workspace secrets db: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let waddr = w.get_waddress().unwrap();

        // Case #1: add symmetric key
        let storagekey =
            CryptoString::from("XSALSA20:L_fPZVo1rGPozl^N)bm2$Dc%xyihXmzV}7w^d0xm").unwrap();

        let keyhash = match add_key(
            &conn,
            &waddr,
            &storagekey,
            "blake2b-256",
            &KeyCategory::Storage,
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding replacement storage key: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #2: get symmetric key
        match get_key(&conn, &keyhash) {
            Ok(v) => {
                if v != storagekey {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: get_key value mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting storage key: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #3: get key by category
        match get_key_by_category(&conn, &KeyCategory::Storage) {
            Ok(v) => {
                if v != storagekey {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: get_key value mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting storage key by category: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }

    #[test]
    fn test_utility() -> Result<(), MensagoError> {
        let testname = String::from("test_utility");
        let test_path = setup_test(&testname);

        let _ = setup_profile(&testname, &test_path)?;

        let mut profile_path = test_path.clone();
        profile_path.push("primary");
        let w = setup_workspace(&testname, &profile_path)?;

        let conn = match w.open_storage() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to workspace storage db: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match check_workspace_exists(&conn, &w.get_waddress().unwrap()) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to find existing workspace: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match check_workspace_exists(
            &conn,
            &WAddress::from("12345678-1234-5678-4321-abcdefabcdef/example.com").unwrap(),
        ) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: passed a nonexistent workspace",
                    testname
                )))
            }
            Err(_) => (),
        };

        Ok(())
    }
}
