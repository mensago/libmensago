mod tests {
    use super::super::demodata::import_demonotes;
    use crate::common::*;
    use libkeycard::*;
    use libmensago::*;

    #[test]
    fn test_notemodel() -> Result<(), MensagoError> {
        let testname = "test_notemodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, mut profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile_mut().unwrap();
        let mut db = match profile.get_db() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: new db conn failed to connect: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

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

    #[test]
    fn test_get_notebooks() -> Result<(), MensagoError> {
        let testname = "test_get_notebooks";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, mut profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile_mut().unwrap();
        let mut db = match profile.get_db() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: new db conn failed to connect: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match import_demonotes(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error importing demo notes: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let notebooks = match get_notebooks(&mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting notebook names: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if notebooks.len() != 2 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: expected 2 notebooks, got {}",
                testname,
                notebooks.len()
            )));
        }

        Ok(())
    }

    #[test]
    fn test_get_notes() -> Result<(), MensagoError> {
        let testname = "test_get_notes";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, mut profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile_mut().unwrap();
        let mut db = match profile.get_db() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: new db conn failed to connect: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match import_demonotes(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error importing demo notes: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let notes = match get_notes(&mut db, "Default") {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting notebook names: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if notes.len() != 2 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: expected 2 notes, got {}",
                testname,
                notes.len()
            )));
        }

        let note = &notes[0];
        if note.rowid != 1 || note.title != "The Pilgrim's Progress" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: first note had unexpected values: {:?}",
                testname, note,
            )));
        }

        let note = &notes[1];
        if note.rowid != 2 || note.title != "Dartpass: README" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: second note had unexpected values: {:?}",
                testname, note,
            )));
        }

        Ok(())
    }

    #[test]
    fn test_update_title_text() -> Result<(), MensagoError> {
        let testname = "test_update_title_text";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, mut profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile_mut().unwrap();
        let mut db = match profile.get_db() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: new db conn failed to connect: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match import_demonotes(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error importing demo notes: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let notes = match get_notes(&mut db, "Default") {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting notebook names: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let noteitem = &notes[1];
        if noteitem.rowid != 2 || noteitem.title != "Dartpass: README" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: test note had unexpected incoming value: {:?}",
                testname, noteitem,
            )));
        }

        let mut note = match NoteModel::load_from_db(&noteitem.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error loading test note content: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match note.update_title(&mut db, "Test Note #2") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error renaming test note: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match note.update_text(&mut db, "Dummy data for test note #2") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error updating test note body text: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match check_db_value(&mut db, "notes", &note.id, "title", &note.title) {
            Ok(_) => (),
            Err(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: test note had wrong title: {}",
                    testname, note.title
                )))
            }
        }

        match check_db_value(&mut db, "notes", &note.id, "body", &note.body) {
            Ok(_) => (),
            Err(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: test note had wrong body: {}",
                    testname, note.body
                )))
            }
        }

        Ok(())
    }
}
