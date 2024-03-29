#[cfg(test)]
mod tests {
    use crate::common::*;
    use eznacl::*;
    use libkeycard::*;
    use libmensago::*;
    use std::path::PathBuf;

    // addentry() is tested by common.rs::test_regcode_user()

    // device() is tested by common.rs::test_regcode_user()

    #[test]
    fn test_devkey() -> Result<(), MensagoError> {
        let testname = "test_devkey";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, _, _, _, mut conn, admin_regdata) = full_test_setup(testname)?;

        let oldpair = EncryptionPair::from_strings(
            ADMIN_PROFILE_DATA["device.public"].as_str(),
            ADMIN_PROFILE_DATA["device.private"].as_str(),
        )?;
        let newpair = EncryptionPair::generate("CURVE25519").unwrap();
        let devid = RandomID::from(&admin_regdata.devid.to_string()).unwrap();

        match devkey(&mut conn, &devid, &oldpair, &newpair) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: devkey error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        conn.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_getwid() -> Result<(), MensagoError> {
        let testname = "test_getwid";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, dbdata, _, _, _, mut conn, _) = full_test_setup(testname)?;

        let wid = match getwid(
            &mut conn,
            &UserID::from("admin").unwrap(),
            Domain::from("example.com").as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: getwid failed: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let admin_wid = RandomID::from(&dbdata["admin_wid"]).unwrap();
        if wid != admin_wid {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: wid mismatch: wanted {}, got {}",
                testname,
                wid.to_string(),
                admin_wid.to_string()
            )));
        }

        conn.disconnect()?;

        Ok(())
    }

    // login() is tested by common.rs::test_regcode_user()

    #[test]
    fn test_orgcard() -> Result<(), MensagoError> {
        let testname = "test_orgcard";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, _, _, _, mut conn, _) = full_test_setup(testname)?;

        let card = match orgcard(&mut conn, 1) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: full card request failed: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        if card.entries.len() != 2 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: entry count mismatch: wanted 2, got {}",
                testname,
                card.entries.len()
            )));
        }

        conn.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_preregister_regcode() -> Result<(), MensagoError> {
        let testname = "test_preregister";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, _, pwhash, _, mut conn, _) = full_test_setup(testname)?;

        let userwid = RandomID::from(&USER1_PROFILE_DATA["wid"]);
        let useruid = UserID::from(&USER1_PROFILE_DATA["uid"]);
        let userdomain = Domain::from(&USER1_PROFILE_DATA["domain"]);
        let userregdata = match preregister(
            &mut conn,
            userwid.as_ref(),
            useruid.as_ref(),
            userdomain.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "preregister() failed in {}: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let devid = RandomID::from(&USER1_PROFILE_DATA["devid"]).unwrap();
        match regcode(
            &mut conn,
            MAddress::from(&USER1_PROFILE_DATA["address"])
                .as_ref()
                .unwrap(),
            &userregdata.regcode,
            &pwhash,
            &devid,
            &EncryptionPair::from_strings(
                &USER1_PROFILE_DATA["device.public"],
                &USER1_PROFILE_DATA["device.private"],
            )
            .unwrap(),
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "use regcode failed in regcode_user: {}",
                    e.to_string()
                )))
            }
        };

        conn.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_register() -> Result<(), MensagoError> {
        let testname = "test_register";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, _, pwhash, _, mut conn, _) = full_test_setup(testname)?;

        let devid = RandomID::generate();
        let devpair = EncryptionPair::generate("CURVE25519")?;
        match register(
            &mut conn,
            UserID::from("csimons").as_ref(),
            &pwhash,
            &devid,
            &devpair,
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: register error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }
        conn.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_reset_password() -> Result<(), MensagoError> {
        let testname = "test_reset_password";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;

        // Now that the admin has been registered and is logged in, prereg a regular user
        let prinfo = match preregister(
            &mut conn,
            Some(&RandomID::from(&USER1_PROFILE_DATA["wid"]).unwrap()),
            Some(&UserID::from(&USER1_PROFILE_DATA["uid"]).unwrap()),
            Some(&Domain::from(&USER1_PROFILE_DATA["domain"]).unwrap()),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error preregistering test user: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        conn.disconnect()?;

        let dns = FakeDNSHandler::new();
        let mut client = match Client::new(&profile_folder.to_string(), Box::new(dns), false) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error initializing client: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match client.get_profile_manager().create_profile("user") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error creating test user profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.get_profile_manager().activate_profile("user") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error activating test user profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let example_com = Domain::from("example.com").unwrap();
        match client.connect(&example_com) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to example.com: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.redeem_regcode(
            &MAddress::from(&USER1_PROFILE_DATA["address"]).unwrap(),
            &prinfo.regcode,
            &USER1_PROFILE_DATA["password"],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error redeeming reg code: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.get_profile_manager().activate_profile("primary") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error reactivating admin profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.login(&MAddress::from("admin/example.com").unwrap()) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error logging in as admin/example.com: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let userwid = &RandomID::from(USER1_PROFILE_DATA.get("wid").unwrap()).unwrap();
        let resetdata = reset_password(client.get_connection_mut(), &userwid, None, None)?;

        client.logout()?;

        match client.get_profile_manager().activate_profile("user") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error reactivating test user profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let newhash = ArgonHash::from_hashstr("$argon2id$v=19$m=65536,t=2,p=1$1ShuDYxOfXPXQeojGGkVZA$5O/qmjf2xJYAixoy2foWNlf9+K8zXs2/zs8XMKNvc8I");
        match passcode(
            client.get_connection_mut(),
            &userwid,
            &resetdata["resetcode"],
            &newhash.to_string(),
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error applying passcode: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        client.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_setpassword() -> Result<(), MensagoError> {
        let testname = "test_setpassword";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, _, pwhash, _, mut conn, _) = full_test_setup(testname)?;

        let badpassword = ArgonHash::from_hashstr(USER1_PROFILE_DATA["passhash"].as_str());
        let newpassword = ArgonHash::from_hashstr(
            "$argon2id$v=19$m=65536,t=2,p=1$CXh8Mzm\
		TlJNrNddm2RqWAg$874zZGneIsc1QyUJcW7O9SRrbgkF0gTKo4xdbJOiZU0",
        );
        match setpassword(&mut conn, &badpassword, &newpassword) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: setpassword allowed a bad password",
                    testname
                )))
            }
            Err(_) => (),
        }

        match setpassword(&mut conn, &pwhash, &newpassword) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: setpassword() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        conn.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_usercard() -> Result<(), MensagoError> {
        let testname = "test_usercard";

        // This is an... involved... test. :( First, all the basic server and admin setup

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

        match regcode_user(
            &mut conn,
            &mut profman,
            &dbdata,
            &ADMIN_PROFILE_DATA,
            &dbdata["admin_regcode"],
            &pwhash,
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: regcode_user error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Now that the admin has been registered and is logged in, prereg a regular user
        let prinfo = match preregister(
            &mut conn,
            Some(&RandomID::from(&USER1_PROFILE_DATA["wid"]).unwrap()),
            Some(&UserID::from(&USER1_PROFILE_DATA["uid"]).unwrap()),
            Some(&Domain::from(&USER1_PROFILE_DATA["domain"]).unwrap()),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error preregistering test user: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        conn.disconnect()?;

        let dns = FakeDNSHandler::new();
        let mut client = match Client::new(&profile_folder.to_string(), Box::new(dns), false) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error initializing client: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match client.get_profile_manager().create_profile("user") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error creating test user profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.get_profile_manager().activate_profile("user") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error activating test user profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let example_com = Domain::from("example.com").unwrap();
        match client.connect(&example_com) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to example.com: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.redeem_regcode(
            &MAddress::from(&USER1_PROFILE_DATA["address"]).unwrap(),
            &prinfo.regcode,
            &USER1_PROFILE_DATA["password"],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error redeeming reg code: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.login(&MAddress::from(&USER1_PROFILE_DATA["address"]).unwrap()) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error logging in as user: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.update_keycard() {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error updating keycard: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match client.update_keycard() {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error updating keycard (second time): {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        client.logout()?;
        client.disconnect()?;

        match conn.connect(config["network"]["listen_ip"].as_str().unwrap(), port) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error reconnecting to server: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let card = match usercard(
            &mut conn,
            &MAddress::from(&USER1_PROFILE_DATA["address"]).unwrap(),
            1,
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting user keycard: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if card.entries.len() != 2 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: expected 2 usercard entries, got: {}",
                testname,
                card.entries.len()
            )));
        }

        conn.disconnect()?;

        Ok(())
    }
}
