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
    fn test_namepartmodel() -> Result<(), MensagoError> {
        let testname = "test_namepartmodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let model =
            NamePartModel::new(&RandomID::from("00000000-1111-2222-3333-444444444444").unwrap());

        match model.add_to_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: add_to_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }
}
