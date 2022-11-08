mod tests {
    use crate::common::*;
    use libmensago::*;
    use libmensago::{DBModel, MensagoError};

    #[test]
    fn test_load_demonotes() -> Result<(), MensagoError> {
        let testname = "test_load_demonotes";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let txtnote = match NoteModel::import(
            "tests/demofiles/pilgrimsprogress.txt",
            DocFormat::Text,
            "The Pilgrim's Progress",
            "Default",
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error reading text file: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        match txtnote.set_in_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding text file to database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let mdnote = match NoteModel::import(
            "tests/demofiles/dartpass_readme.md",
            DocFormat::Markdown,
            "Dartpass: README",
            "Default",
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error reading Markdown file: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        match mdnote.set_in_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding Markdown file to database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        let sftmnote = match NoteModel::import(
            "tests/demofiles/roadnottaken.sftm",
            DocFormat::SFTM,
            "The Road Not Taken",
            "Default",
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error reading SFTM file: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        match sftmnote.set_in_db(&mut db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding SFTM file to database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }
}
