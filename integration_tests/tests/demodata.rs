use libmensago::*;
use libmensago::{DBModel, MensagoError};

pub fn import_demonotes(db: &mut DBConn) -> Result<(), MensagoError> {
    let txtnote = NoteModel::import(
        "tests/demofiles/pilgrimsprogress.txt",
        DocFormat::Text,
        "The Pilgrim's Progress",
        "Default",
    )?;
    txtnote.set_in_db(db)?;

    let mdnote = NoteModel::import(
        "tests/demofiles/dartpass_readme.md",
        DocFormat::Markdown,
        "Dartpass: README",
        "Default",
    )?;
    mdnote.set_in_db(db)?;

    let sftmnote = NoteModel::import(
        "tests/demofiles/roadnottaken.sftm",
        DocFormat::SFTM,
        "The Road Not Taken",
        "SFTM",
    )?;
    sftmnote.set_in_db(db)?;

    Ok(())
}

mod tests {
    use super::import_demonotes;
    use crate::common::*;
    use libmensago::MensagoError;

    #[test]
    fn test_load_demonotes() -> Result<(), MensagoError> {
        let testname = "test_load_demonotes";

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

        Ok(())
    }
}
