mod tests {
    use crate::common::*;
    use libmensago::*;

    #[test]
    fn test_dbconn_execute() -> Result<(), MensagoError> {
        // This test is also officially responsible for testing connect() and disconnect()
        let testname = "test_dbconn_execute";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        //
        // Calling setup_db_test() is really overkill for what this test needs, but the extra
        // setup work done is worth not having to write custom test setup logic.
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
        //
        // Calling setup_db_test() is really overkill for what this test needs, but the extra
        // setup work done is worth not having to write custom test setup logic.
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
				'value' TEXT NOT NULL
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

        let testdata = vec![
            ["name1", "value1"],
            ["name2", "value2"],
            ["name3", "value3"],
        ];
        for item in testdata.iter() {
            match db.execute("INSERT INTO test_table(name,value) VALUES(?1,?2)", item) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: error populating test table: {}",
                        testname,
                        e.to_string()
                    )))
                }
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
        if rows[0][0] != "name1" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: query() - first value should have been 'name1', got '{}'",
                testname, rows[0][0],
            )));
        }
        if rows[0][1] != "value1" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: query() - second value should have been 'value1', got '{}'",
                testname, rows[0][1],
            )));
        }

        Ok(())
    }

    // TODO: implement test case for query_row()
}
