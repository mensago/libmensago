mod tests {
    use crate::common::*;
    use libkeycard::*;
    use libmensago::*;

    #[test]
    fn test_dbconn_connect_disconnect() -> Result<(), MensagoError> {
        // This test is also officially responsible for testing connect() and disconnect()
        let testname = "test_dbconn_connect_disconnect";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        //
        // Calling setup_db_test() is really overkill for what this test needs, but the extra
        // setup work done is worth not having to write custom test setup logic.
        let (_, _, mut profman) = setup_db_test(testname)?;

        match profman.create_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{} failed to create test profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        assert!(profman
            .get_active_profile_mut()
            .unwrap()
            .dbconn
            .is_connected());

        match profman.activate_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{} failed to activate secondary profile: {}",
                    testname,
                    e.to_string()
                )))
            }
        }
        assert!(!profman.get_profile_mut(0).unwrap().dbconn.is_connected());

        Ok(())
    }

    #[test]
    fn test_dbconn_execute() -> Result<(), MensagoError> {
        // This test is also officially responsible for testing connect() and disconnect()
        let testname = "test_dbconn_execute";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;
        let profile = profman.get_active_profile().unwrap();

        let mut db = DBConn::new();
        let mut dbpath = profile.path.clone();
        dbpath.push("storage.db");
        match db.connect(&dbpath) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // To test execute, we're going to add a device session as documented in the auth module
        match db.execute(
            "INSERT INTO sessions(address, devid, devname, public_key, private_key, os)
			VALUES(?1,?2,?3,?4,?5,?6)",
            [
                &USER1_PROFILE_DATA["waddress"],
                &USER1_PROFILE_DATA["devid"],
                &USER1_PROFILE_DATA["name"],
                &USER1_PROFILE_DATA["device.public"],
                &USER1_PROFILE_DATA["device.private"],
                "linux",
            ],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error calling execute(): {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match db.disconnect() {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error disconnecting from database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }
        Ok(())
    }

    #[test]
    fn test_dbconn_queries() -> Result<(), MensagoError> {
        let testname = "test_dbconn_queries";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;
        let profile = profman.get_active_profile().unwrap();

        let mut db = DBConn::new();
        let mut dbpath = profile.path.clone();
        dbpath.push("storage.db");
        match db.connect(&dbpath) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error connecting to database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Set up the query test conditions by creating a test table and added a few rows of test
        // data

        match db.execute(
            "CREATE TABLE 'test_table' (
				'name' TEXT NOT NULL,
				'value' TEXT NOT NULL,
                'value2' INTEGER NOT NULL
			);",
            [],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error creating test table: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        match db.execute(
            "INSERT INTO test_table(name,value,value2) VALUES(?1,?2,?3)",
            rusqlite::params!["name1", "value1", 1],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error populating test table step 1: {}",
                    testname,
                    e.to_string()
                )))
            }
        }
        match db.execute(
            "INSERT INTO test_table(name,value,value2) VALUES(?1,?2,?3)",
            rusqlite::params!["name2", "value2", 2],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error populating test table step 2: {}",
                    testname,
                    e.to_string()
                )))
            }
        }
        match db.execute(
            "INSERT INTO test_table(name,value,value2) VALUES(?1,?2,?3)",
            rusqlite::params!["name3", "value3", 3],
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error populating test table step 3: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Now that we have the test data, we will test query() first.
        let rows = match db.query("SELECT * FROM test_table", []) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error calling query_row(): {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        if rows.len() != 3 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: query() - expected 3 rows, got {}",
                testname,
                rows.len(),
            )));
        }
        if rows[0][0].to_string() != "name1" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: query() - first value should have been 'name1', got '{}'",
                testname, rows[0][0],
            )));
        }
        if rows[0][1].to_string() != "value1" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: query() - second value should have been 'value1', got '{}'",
                testname, rows[0][1],
            )));
        }
        if rows[0][2] != DBValue::Integer(1) {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: query() - third value should have been 1, got '{}'",
                testname,
                rows[0][2].to_string(),
            )));
        }

        Ok(())
    }

    #[test]
    fn test_dbconn_updates() -> Result<(), MensagoError> {
        let testname = "test_dbconn_updates";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, mut profman) = setup_db_test(testname)?;
        let profile = profman.get_active_profile_mut().unwrap();
        let mut db = profile.get_db()?;

        // Case #1: subscribe() x 2

        let (tx1, rx1) = crossbeam_channel::unbounded();
        let _ = match DBConn::subscribe(DBUpdateChannel::Notes, tx1) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding subscriber 1 to note updates: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        let (tx2, rx2) = crossbeam_channel::unbounded();
        let rxid2 = match DBConn::subscribe(DBUpdateChannel::Notes, tx2) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding subscriber 2 to note updates: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #2: Getting updates to both subscribers

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

        let mut event1 = match rx1.recv() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error sub1 getting first update: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        let event2 = match rx2.recv() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error sub2 getting first update: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if event1 != event2 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: first update value mismatch for both subscribers",
                testname
            )));
        }
        if event1.event != DBEVENT_INSERT || event1.table != "notes" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: bad values in first update message: {:?}",
                testname, event1
            )));
        }

        // Case #3: unsubscribe()

        match DBConn::unsubscribe(DBUpdateChannel::Notes, rxid2) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error removing subscriber 2 from note updates: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case  #4: Modification update

        model.update_title(db, "Untitled 2")?;
        event1 = match rx1.recv() {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error sub1 getting modification update: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        if event1.event != DBEVENT_UPDATE || event1.table != "notes" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: bad values in second update message: {:?}",
                testname, event1
            )));
        }

        // TODO: finish test_dbconn_updates()

        Ok(())
    }
}
