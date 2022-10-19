mod tests {
    use crate::common::*;
    use libkeycard::*;
    use libmensago::*;

    #[test]
    fn test_notemodel() -> Result<(), MensagoError> {
        let testname = "test_notemodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let modelid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let mut model = NoteModel::new("Untitled", DocFormat::Text, "Default");
        model.id = modelid.clone();
        model.body = String::from("This is some text.\n");

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

        match check_db_value(&mut db, "notes", &model.id, "title", "Untitled") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db value check error for gender: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Update in db
        model.tags = vec![String::from("tag1"), String::from("tag2")];
        match model.set_in_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db() update error: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match check_db_value(&mut db, "notes", &model.id, "tags", "tag1,tag2") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db value check error for prefix: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Load from db
        let loadmodel = match NoteModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.title != "Untitled" || loadmodel.body != "This is some text.\n" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected Untitled/'This is some text', got '{}/{}'",
                testname, loadmodel.title, loadmodel.body,
            )));
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

        match check_db_value(&mut db, "notes", &model.id, "body", "") {
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
