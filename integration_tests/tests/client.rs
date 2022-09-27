#[cfg(test)]
mod tests {
    use crate::common::*;
    use libkeycard::*;
    use libmensago::*;

    #[test]
    fn test_client_login() -> Result<(), MensagoError> {
        let testname = "test_client_login";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;
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

        client.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_client_preregister() -> Result<(), MensagoError> {
        let testname = "test_client_preregister";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;
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

        // Test Case #1: No data supplied
        match client.preregister(None, None) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: empty prereg failed: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Test Case #2: Workspace ID supplied
        let uid =
            UserID::from_wid(&RandomID::from("33333333-3333-3333-3333-333333333333").unwrap());
        match client.preregister(Some(&uid), None) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: wid prereg failed: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Test Case #3: User ID supplied
        let uid = UserID::from(&USER1_PROFILE_DATA["uid"]).unwrap();
        match client.preregister(Some(&uid), None) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: wid prereg failed: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        client.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_client_regcode() -> Result<(), MensagoError> {
        let testname = "test_client_regcode";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;
        conn.disconnect()?;

        // This test is *involved*:
        // 1. Log in as admin, prereg user, and log out.
        // 2. Create a second profile for the user
        // 3. Use the regcode from earlier to register the user's first device
        // 4. Log in as the user and call update_keycard() twice, once to upload the root and a
        //    second time to chain and upload a second one

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

        let uid = UserID::from(&USER1_PROFILE_DATA["uid"]).unwrap();
        let prinfo = match client.preregister(Some(&uid), None) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: wid prereg failed: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match client.logout() {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error logging out from admin/example.com: {}",
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

        client.disconnect()?;

        Ok(())
    }

    #[test]
    fn test_client_register() -> Result<(), MensagoError> {
        let testname = "test_client_register";

        // The list of full data is as follows:
        // let (config, db, dbdata, profile_folder, pwhash, profman, mut conn, admin_regdata) =
        // 	full_test_setup(testname)?;
        let (_, _, _, profile_folder, _, _, mut conn, _) = full_test_setup(testname)?;
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

        match client.register(
            &example_com,
            &USER1_PROFILE_DATA["password"],
            Some(&UserID::from(&USER1_PROFILE_DATA["uid"]).unwrap()),
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error registering test user: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

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

        // We call update_keycard() twice to ensure that both root keycard setup and chaining both
        // work correctly
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

        client.disconnect()?;

        Ok(())
    }
}
