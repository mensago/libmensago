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

    fn check_db_value(
        conn: &mut rusqlite::Connection,
        tablename: &str,
        id: &RandomID,
        column: &str,
        value: &str,
    ) -> Result<(), MensagoError> {
        if tablename.len() == 0 || column.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        let mut stmt = conn.prepare("SELECT ?1 FROM ?2 WHERE id = ?3")?;
        let dbvalue = match stmt.query_row(&[column, tablename, &id.to_string()], |row| {
            Ok(row.get::<usize, String>(0).unwrap())
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        if dbvalue == value {
            return Ok(());
        }

        Err(MensagoError::ErrDatabaseException(format!(
            "wanted {}, got {}",
            value, dbvalue,
        )))
    }

    #[test]
    fn test_namepartmodel() -> Result<(), MensagoError> {
        let testname = "test_namepartmodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let modelid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let model = NamePartModel::new(&modelid);

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

        match check_db_value(&mut db, "contact_nameparts", &modelid, "priority", "0") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: add_to_db value check error for priority: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }
}
