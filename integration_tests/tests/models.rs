mod tests {
    use crate::common::*;
    use eznacl::CryptoString;
    use libkeycard::*;
    use libmensago::*;
    use mime::Mime;
    use std::path::PathBuf;
    use std::str::FromStr;
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
    fn test_stringmodel() -> Result<(), MensagoError> {
        let testname = "test_stringmodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let itemtype = "social";
        let mut model = StringModel::new(&conid, itemtype);
        model.label = String::from("Twitter");

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
            ("conid", conid.to_string()),
            ("label", String::from("Twitter")),
            ("value", String::new()),
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_keyvalue", &model.id, pair.0, &pair.1) {
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
        model.value = String::from("@test");
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

        fields[3] = ("value", String::from("@test"));
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_keyvalue", &model.id, pair.0, &pair.1) {
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
        let loadmodel = match StringModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.label != "Twitter" || loadmodel.value != "@test" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected '{}'/'@test', got '{}/{}'",
                testname, conid, loadmodel.label, loadmodel.value
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

        match check_db_value(&mut db, "contact_keyvalue", &model.id, "value", "") {
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
                    "{}: set_in_db() update error: {}",
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

        // Load from db
        let loadmodel = match NamePartModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.part_type != NamePartType::Suffix || loadmodel.value != "Jr." {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected parttype = 'suffix' and value = 'Jr.'. 
                Got '{}' and value '{}'",
                testname, loadmodel.part_type, loadmodel.value
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

    #[test]
    fn test_namemodel() -> Result<(), MensagoError> {
        let testname = "test_namemodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let mut model = NameModel::new(&conid, "Corbin");
        model.family_name = String::from("Simons");

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

        match check_db_value(&mut db, "contact_names", &model.id, "given_name", "Corbin") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_in_db value check error for given name: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Update in db
        model.prefix = String::from("Mr.");
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

        match check_db_value(&mut db, "contact_names", &model.id, "prefix", "Mr.") {
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
        let loadmodel = match NameModel::load_from_db(&conid, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.given_name != "Corbin" || loadmodel.family_name != "Simons" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected 'Corbin Simons', got '{} {}'",
                testname, loadmodel.given_name, loadmodel.family_name
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

        match check_db_value(&mut db, "contact_names", &model.id, "prefix", "Mr.") {
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
    fn test_mensagomodel() -> Result<(), MensagoError> {
        let testname = "test_mensagomodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let wid = RandomID::from("11111111-1111-1111-1111-111111111111").unwrap();
        let domain = Domain::from("example.com").unwrap();
        let mut model = MensagoModel::new(&conid, "Work", None, &wid, &domain);

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
            ("conid", conid.to_string()),
            ("label", String::from("Work")),
            ("uid", String::new()),
            ("wid", wid.to_string()),
            ("domain", domain.to_string()),
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_mensago", &model.id, pair.0, &pair.1) {
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

        // Update db
        let uid = UserID::from("csimons").unwrap();
        model.uid = Some(uid.clone());
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

        fields[3] = ("uid", uid.to_string());
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_mensago", &model.id, pair.0, &pair.1) {
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
        let loadmodel = match MensagoModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.label != "Work" || loadmodel.domain.to_string() != "example.com" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected 'Work' and 'example.com', got '{} {}'",
                testname, loadmodel.label, loadmodel.domain
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

        match check_db_value(&mut db, "contact_mensago", &model.id, "uid", "csimons") {
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
    fn test_keymodel() -> Result<(), MensagoError> {
        let testname = "test_keymodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_secrets()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let testkey =
            CryptoString::from("CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az").unwrap();
        let mut model = KeyModel::new(&conid, "Work", KeyCategory::Encryption, &testkey);

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
            ("conid", conid.to_string()),
            ("label", String::from("Work")),
            ("category", String::from("encryption")),
            ("value", testkey.to_string()),
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_keys", &model.id, pair.0, &pair.1) {
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

        // Update db
        model.label = String::from("Home");
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

        fields[2] = ("label", String::from("Home"));
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_keys", &model.id, pair.0, &pair.1) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: set_in_db updatevalue check error for {}: {}",
                        testname,
                        pair.0,
                        e.to_string()
                    )))
                }
            }
        }

        // Load from db
        let loadmodel = match KeyModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.label != "Home"
            || loadmodel.key.to_string() != "CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az"
        {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected 'Home' and 
                'CURVE25519:SNhj2K`hgBd8>G>lW$!pXiM7S-B!Fbd9jT2&{{Az', got '{} {}'",
                testname, loadmodel.label, loadmodel.key
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

        match check_db_value(&mut db, "contact_keys", &model.id, "category", "encryption") {
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
    fn test_addressmodel() -> Result<(), MensagoError> {
        let testname = "test_addressmodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let mut model = AddressModel::new(&conid, "Home");
        model.street = String::from("1313 Mockingbird Lane");
        model.country = String::from("United States");

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
            ("conid", conid.to_string()),
            ("label", String::from("Home")),
            ("street", String::from("1313 Mockingbird Lane")),
            ("country", String::from("United States")),
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_address", &model.id, pair.0, &pair.1) {
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

        // Update db
        model.label = String::from("Other");
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

        fields[2] = ("label", String::from("Other"));
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_address", &model.id, pair.0, &pair.1) {
                Ok(_) => (),
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: set_in_db update value check error for {}: {}",
                        testname,
                        pair.0,
                        e.to_string()
                    )))
                }
            }
        }

        // Load from db
        let loadmodel = match AddressModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.label != "Other" || loadmodel.country != "United States" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected 'Other' and
                'United States', got '{} {}'",
                testname, loadmodel.label, loadmodel.country
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

        match check_db_value(&mut db, "contact_address", &model.id, "label", "") {
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
    fn test_photomodel() -> Result<(), MensagoError> {
        let testname = "test_photomodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let imgtype = Mime::from_str("image/webp").unwrap();
        let imgdata = vec![65, 66, 67, 68, 69];
        let mut model = PhotoModel::new(&conid, &imgtype, &imgdata);

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
            ("conid", conid.to_string()),
            ("mime", String::from("image/webp")),
            // Can't check binary data with check_db_value(). Oh well. *shrug*
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_photo", &model.id, pair.0, &pair.1) {
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
        model.mime_type = Mime::from_str("image/png").unwrap();
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

        fields[2] = ("mime", String::from("image/png"));
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_photo", &model.id, pair.0, &pair.1) {
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
        let loadmodel = match PhotoModel::load_from_db(&conid, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.contact_id != conid || loadmodel.mime_type.to_string() != "image/png" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected {}/'image/png', got '{}/{}'",
                testname, conid, loadmodel.contact_id, loadmodel.mime_type
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

        match check_db_value(&mut db, "contact_photo", &model.id, "mime", "") {
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
    fn test_filemodel() -> Result<(), MensagoError> {
        let testname = "test_filemodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;

        let conid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let filetype = Mime::from_str("text/plain").unwrap();
        let filedata = vec![65, 66, 67, 68, 69];
        let filename = String::from("test.txt");
        let mut model = FileModel::new(&conid, &filename, &filetype, &filedata);

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
            ("conid", conid.to_string()),
            ("name", filename.clone()),
            ("mime", filetype.to_string()),
            // Can't check binary data with check_db_value(). Oh well. *shrug*
        ];
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_files", &model.id, pair.0, &pair.1) {
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
        model.mime_type = Mime::from_str("text/markdown").unwrap();
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
        fields[3] = ("mime", String::from("text/markdown"));
        for pair in fields.iter() {
            match check_db_value(&mut db, "contact_files", &model.id, pair.0, &pair.1) {
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
        let loadmodel = match FileModel::load_from_db(&model.id, &mut db) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: load_from_db() error: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if loadmodel.contact_id != conid || loadmodel.mime_type.to_string() != "text/markdown" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected {}/'text/markdown', got '{}/{}'",
                testname, conid, loadmodel.contact_id, loadmodel.mime_type
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

        match check_db_value(&mut db, "contact_files", &model.id, "mime", "") {
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
    fn test_contactmodel() -> Result<(), MensagoError> {
        let testname = "test_contactmodel";

        // The list of full data is as follows:
        // let (config, pwhash, profman) = setup_db_test(testname)?;
        let (_, _, profman) = setup_db_test(testname)?;

        let profile = profman.get_active_profile().unwrap();
        let mut db = profile.open_storage()?;
        let mut secrets = profile.open_secrets()?;

        let modelid = RandomID::from("00000000-1111-2222-3333-444444444444").unwrap();
        let mut model =
            ContactDataModel::new("Corbin", EntityType::Individual, false, Some(&modelid));

        model.name.family_name = String::from("Simons");
        model.gender = String::from("male");
        model.organization = String::from("Acme Widgets, Inc.");

        let mut twitter = StringModel::new(&model.id, "social");
        twitter.label = String::from("Twitter");
        twitter.value = String::from("&test");
        model.social.push(twitter);

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

        match check_db_value(&mut db, "contacts", &model.id, "gender", "male") {
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
        model.languages = vec![String::from("en"), String::from("es")];
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

        match check_db_value(&mut db, "contacts", &model.id, "languages", "en,es") {
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
        let loadmodel =
            match ContactDataModel::load_from_db(&model.id, &mut db, &mut secrets, false) {
                Ok(v) => v,
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: load_from_db() error: {}",
                        testname,
                        e.to_string()
                    )))
                }
            };

        if loadmodel.gender != "male" || loadmodel.organization != "Acme Widgets, Inc." {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: load_from_db value mismatch: expected male/'Acme Widgets, Inc.', got '{}/{}'",
                testname, loadmodel.gender, loadmodel.organization
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

        match check_db_value(&mut db, "contacts", &model.id, "gender", "") {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: delete_from_db failed to delete row",
                    testname,
                )))
            }
            Err(_) => (),
        }

        // TODO: Finish testing ContactDataModel

        Ok(())
    }
}
