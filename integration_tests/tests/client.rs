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
        let uid = UserID::from("csimons").unwrap();
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
            "MyS3cretPassw*rd",
            Some(&UserID::from("csimons").unwrap()),
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

        client.disconnect()?;

        Ok(())
    }
}
