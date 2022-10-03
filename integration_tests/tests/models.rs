mod tests {
    use crate::common::*;
    use libkeycard::*;
    use libmensago::*;
    use std::path::PathBuf;
    use toml_edit::Document;

    fn setup_db_test(
        testname: &str,
    ) -> Result<(Document, ArgonHash, ProfileManager), MensagoError> {
        let mut config = load_server_config(true)?;
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

        Ok((config, pwhash, profman))
    }

    #[test]
    fn test_stringmodel() -> Result<(), MensagoError> {
        let testname = "test_stringmodel";

        let (_, _, _) = setup_db_test(testname)?;

        Ok(())
    }
}
