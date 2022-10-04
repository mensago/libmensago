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

        // Doing regular string substitution in a SQL query is usually a recipe for an injection
        // attack. We're doing this here because (1) using the regular syntax for inserting values
        // into queries creates syntax errors when used for table names and (2) we control that
        // part of the query. We're also doing the same thing for the column because the escaping
        // done for substitution causes the column name to be returned from the query instead of
        // the value of the row in that column. Not great, but it *is* safe in this instance.
        let mut stmt =
            conn.prepare(format!("SELECT {} FROM {} WHERE id = ?1", column, tablename).as_str())?;

        let dbvalue = match stmt.query_row(&[&id.to_string()], |row| {
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

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let mut model = NamePartModel::new(&conid);

        // Add to db
        match model.set_in_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match check_db_value(&mut db, "contact_nameparts", &model.id, "priority", "0") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db value check error for priority: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Update in db
        model.part_type = NamePartType::Suffix;
        model.value = String::from("Jr.");
        match model.set_in_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match check_db_value(&mut db, "contact_nameparts", &model.id, "value", "Jr.") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db value check error for priority: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Delete from db
        match model.delete_from_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: delete_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match check_db_value(&mut db, "contact_nameparts", &model.id, "value", "Jr.") {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: delete_from_db failed to delete row",
                    testname,
                )))
            }
            Err(_) => (),
        }

        Ok(())
    }
}
