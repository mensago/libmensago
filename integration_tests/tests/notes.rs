mod tests {
    use crate::common::*;
    use libkeycard::*;
    use libmensago::*;
    use mime::Mime;
    use std::str::FromStr;

    #[test]
    fn test_attachmentmodel() -> Result<(), MensagoError> {
        let testname = "test_attachmentmodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let docid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let filetype = Mime::from_str("text/plain").unwrap();
        let filedata = vec![65, 66, 67, 68, 69];
        let filename = String::from("test.txt");
        let mut model = AttachmentModel::from_raw(&docid, &filename, &filetype, &filedata);

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

        let mut fields = vec![
            ("id", model.id.to_string()),
            ("docid", docid.to_string()),
            ("name", filename.clone()),
            ("mimetype", filetype.to_string()),
            // Can't check binary data with check_db_value(). Oh well. *shrug*
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "attachments", &model.id, pair.0, &pair.1) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: set_in_db value check error for field {}: {}",
                        testname,
                        pair.0,
                        e.to_string()
                    )))
                }
            }
        }

        // Update in db
        model.name = String::from("test2.txt");
        model.mimetype = Mime::from_str("text/markdown").unwrap();
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

        fields[2] = ("name", String::from("test2.txt"));
        fields[3] = ("mimetype", String::from("text/markdown"));
        for pair in fields.iter() {
            match check_db_value(&mut db, "attachments", &model.id, pair.0, &pair.1) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: set_in_db value check error for {}: {}",
                        testname,
                        pair.0,
                        e.to_string()
                    )))
                }
            }
        }

        // Load from db
        let loadmodel = match AttachmentModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.docid != docid || loadmodel.mimetype.to_string() != "text/markdown" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected {}/'text/markdown', got '{}/{}'",
                testname, docid, loadmodel.docid, loadmodel.mimetype
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

        match check_db_value(&mut db, "attachments", &model.id, "mime", "") {
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
