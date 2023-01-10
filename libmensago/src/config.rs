//! The config module is dedicated to storing application settings in the same database as the rest
//! of the user data.

use crate::{base::*, dbconn::*};
use std::collections::HashMap;
use std::fmt;

/// ConfigScope defines the scope of a configuration setting.
/// - Global: Setting which applies to the application as a whole, regardless of platform or architecture. A lot of user preferences will go here, such as the theme.
/// - Platform: A setting which is specific to the operating system. Settings in this scope are usually platform-specific, such as the preferred download location for files
/// - Architecture: Settings in this scope are specific to the platform *and* processor architecture, such as Linux on AMD64 vs Linux on ARM or RISC-V. This scope is not generally used.
/// - Local: Settings in this scope are specific to the device, and unlike the other scopes, will not be synchronized across devices.
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum ConfigScope {
    Global,
    Platform,
    Architecture,
    Local,
}

impl ConfigScope {
    pub fn from(s: &str) -> Option<ConfigScope> {
        match &*s.to_lowercase() {
            "global" => Some(ConfigScope::Global),
            "platform" => Some(ConfigScope::Platform),
            "architecture" => Some(ConfigScope::Architecture),
            "local" => Some(ConfigScope::Local),
            _ => None,
        }
    }
}

impl fmt::Display for ConfigScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConfigScope::Global => write!(f, "global"),
            ConfigScope::Platform => write!(f, "platform"),
            ConfigScope::Architecture => write!(f, "architecture"),
            ConfigScope::Local => write!(f, "local"),
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone)]
struct ConfigField {
    pub scope: ConfigScope,
    pub scopevalue: String,
    pub value: String,
}

/// The Config class is just a hash map for holding strings containing app configuration
/// information with some methods to make usage easier
#[derive(Debug, Clone)]
pub struct Config {
    data: HashMap<String, ConfigField>,
    modified: Vec<String>,
    signature: String,
}

impl Config {
    /// Creates a new empty AppConfig instance
    pub fn new(signature: &str) -> Config {
        Config {
            data: HashMap::<String, ConfigField>::new(),
            modified: Vec::<String>::new(),
            signature: String::from(signature),
        }
    }

    /// Deletes the specified field
    pub fn delete(&mut self, field: &str) -> Result<(), MensagoError> {
        if self.has(field) {
            self.data.remove(field);
            Ok(())
        } else {
            Err(MensagoError::ErrNotFound)
        }
    }

    /// Convenience method which instantiates a new instance and loads all values from the database
    pub fn from_db(conn: &mut DBConn) -> Result<Config, MensagoError> {
        let mut c = Config::new("");
        c.load_from_db(conn)?;
        Ok(c)
    }

    /// Gets a field value
    pub fn get(&self, field: &str) -> Result<&str, MensagoError> {
        match self.data.get(field) {
            Some(v) => Ok(&v.value),
            None => Err(MensagoError::ErrNotFound),
        }
    }

    /// Gets a field value.
    pub fn get_int(&self, field: &str) -> Result<isize, MensagoError> {
        let field = match self.data.get(field) {
            Some(v) => v,
            None => return Err(MensagoError::ErrNotFound),
        };

        match field.value.parse::<isize>() {
            Ok(v) => Ok(v),
            Err(_) => Err(MensagoError::ErrTypeMismatch),
        }
    }

    /// Gets the scope of a field
    pub fn get_scope(&self, field: &str) -> Result<(ConfigScope, &str), MensagoError> {
        let f = match self.data.get(field) {
            Some(v) => v,
            None => return Err(MensagoError::ErrNotFound),
        };

        Ok((f.scope, &f.scopevalue))
    }

    /// Gets the application signature for the configuration
    #[inline]
    pub fn get_signature(&self) -> String {
        self.signature.clone()
    }

    /// Returns true if the table has a specific field
    #[inline]
    pub fn has(&self, field: &str) -> bool {
        self.data.get(field).is_some()
    }

    /// Returns true if the instance has been modified since the last call to save_to_db()
    #[inline]
    pub fn is_modified(&self) -> bool {
        self.modified.len() > 0
    }

    /// Loads all fields from the database. NOTE: this call completely clears all data from the
    /// object prior to loading new values
    pub fn load_from_db(&mut self, conn: &mut DBConn) -> Result<(), MensagoError> {
        // Regardless of the outcome, we need to have a nice clean start
        self.data.clear();
        self.modified.clear();

        self.ensure_dbtable(conn)?;

        // The table exists, so load up all values from it
        // let mut stmt = conn.prepare("SELECT fname,scope,scopevalue,fvalue FROM appconfig")?;

        // let mut rows = match stmt.query([]) {
        //     Ok(v) => v,
        //     Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        // };

        // let mut option_row = match rows.next() {
        //     Ok(v) => v,
        //     Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        // };

        // while option_row.is_some() {
        //     let row = option_row.unwrap();
        //     let fscope = match ConfigScope::from(&row.get::<usize, String>(1).unwrap()) {
        //         Some(v) => v,
        //         None => {
        //             return Err(MensagoError::ErrDatabaseException(format!(
        //                 "Bad scope {} for field {}",
        //                 &row.get::<usize, String>(1).unwrap(),
        //                 &row.get::<usize, String>(0).unwrap()
        //             )))
        //         }
        //     };
        //     self.data.insert(
        //         String::from(&row.get::<usize, String>(0).unwrap()),
        //         ConfigField {
        //             scope: fscope,
        //             scopevalue: String::from(&row.get::<usize, String>(2).unwrap()),
        //             value: String::from(&row.get::<usize, String>(3).unwrap()),
        //         },
        //     );
        //     option_row = match rows.next() {
        //         Ok(v) => v,
        //         Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        //     };
        // }
        let rows = conn.query("SELECT fname,scope,scopevalue,fvalue FROM appconfig", [])?;
        if rows.len() == 0 {
            return Ok(());
        }
        if rows[0].len() != 4 {
            return Err(MensagoError::ErrSchemaFailure);
        }

        for row in rows {
            let fscope = match ConfigScope::from(&row[1].to_string()) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad scope {} for field {}",
                        row[1], row[0]
                    )))
                }
            };
            self.data.insert(
                String::from(&row[0].to_string()),
                ConfigField {
                    scope: fscope,
                    scopevalue: String::from(&row[2].to_string()),
                    value: String::from(&row[3].to_string()),
                },
            );
        }

        self.signature = match self.data.get("application_signature") {
            Some(v) => v.value.clone(),
            None => String::new(),
        };

        Ok(())
    }

    /// Saves all fields to the database. NOTE: this will completely clear the existing table of
    /// configuration in the database backend, so be sure you have everything the way you want it
    /// before calling this.
    pub fn save_to_db(&mut self, conn: &mut DBConn) -> Result<(), MensagoError> {
        conn.execute("DROP TABLE IF EXISTS appconfig", [])?;

        self.ensure_dbtable(conn)?;

        // Save all values to the table. Unfortunately, this isn't as fast as it could be because
        // we can't validate the field values in any way, so we can't add all fields in batch.
        // Thankfully, we shouldn't be dealing with more than a few dozen to a few thousand
        // values.
        for (fname, field) in &self.data {
            conn.execute(
                "INSERT INTO appconfig (fname,scope,scopevalue,fvalue) VALUES(?1,?2,?3,?4);",
                [
                    fname,
                    &field.scope.to_string(),
                    &field.scopevalue,
                    &field.value,
                ],
            )?;
        }

        self.modified.clear();

        Ok(())
    }

    /// Sets a field value. Note that setting a value requires deciding what scope to which the
    /// field belongs and setting it accordingly. See documentation on the ConfigScope structure
    /// for more information.
    pub fn set(
        &mut self,
        field: &str,
        scope: ConfigScope,
        scopevalue: &str,
        value: &str,
    ) -> Result<(), MensagoError> {
        if field.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        self.data.insert(
            String::from(field),
            ConfigField {
                scope: scope,
                scopevalue: String::from(scopevalue),
                value: String::from(value),
            },
        );
        self.modified.push(String::from(field));

        Ok(())
    }

    /// Sets a field value only if it doesn't exist already. This call will flag the object as
    /// modified only if it makes a change.
    #[inline]
    pub fn set_if_not_exist(
        &mut self,
        field: &str,
        scope: ConfigScope,
        scopevalue: &str,
        value: &str,
    ) -> Result<(), MensagoError> {
        if field.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        if self.has(field) {
            Ok(())
        } else {
            self.set(field, scope, scopevalue, value)
        }
    }

    /// Sets an integer field value only if it doesn't exist already. This call will flag the
    /// object as modified only if it makes a change.
    #[inline]
    pub fn set_int_if_not_exist(
        &mut self,
        field: &str,
        scope: ConfigScope,
        scopevalue: &str,
        value: isize,
    ) -> Result<(), MensagoError> {
        if field.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        if self.has(field) {
            Ok(())
        } else {
            self.set_int(field, scope, scopevalue, value)
        }
    }

    /// Sets an integer field value. Note that setting a value requires deciding what scope to
    /// which the field belongs and setting it accordingly. See documentation on the ConfigScope
    /// structure for more information.
    pub fn set_int(
        &mut self,
        field: &str,
        scope: ConfigScope,
        scopevalue: &str,
        value: isize,
    ) -> Result<(), MensagoError> {
        if field.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        self.data.insert(
            String::from(field),
            ConfigField {
                scope: scope,
                scopevalue: String::from(scopevalue),
                value: value.to_string(),
            },
        );
        self.modified.push(String::from(field));

        Ok(())
    }

    /// Changes the scope of a field.
    pub fn set_scope(
        &mut self,
        field: &str,
        scope: ConfigScope,
        scopevalue: &str,
    ) -> Result<(), MensagoError> {
        let mut f = match self.data.get(field) {
            Some(v) => v.clone(),
            None => return Err(MensagoError::ErrNotFound),
        };

        f.scope = scope;
        f.scopevalue = String::from(scopevalue);
        self.data.insert(String::from(field), f);

        Ok(())
    }

    /// Sets the application signature for the configuration
    pub fn set_signature(&mut self, signature: &str) -> Result<(), MensagoError> {
        self.signature = String::from(signature);
        self.set("application_signature", ConfigScope::Global, "", signature)
    }

    /// Saves modified values to the database. In general this should be faster than saving the
    /// entire object to the database.
    pub fn update_db(&mut self, conn: &mut DBConn) -> Result<(), MensagoError> {
        // Save everything if it doesn't already exist
        match conn.exists(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='appconfig'",
            [],
        ) {
            Ok(v) => {
                if !v {
                    return self.save_to_db(conn);
                }
            }
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        // Save all values to the table
        for fname in &self.modified {
            let field = match self.data.get(fname) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "BUG: modified item {} missing in database",
                        fname
                    )))
                }
            };

            match conn.exists("SELECT fname FROM appconfig WHERE fname=?1", [fname]) {
                Ok(v) => {
                    let cmd = if v {
                        String::from(
                            "UPDATE appconfig SET scope=?2,scopevalue=?3,fvalue=?4 WHERE fname=?1;",
                        )
                    } else {
                        String::from(
                            "INSERT INTO appconfig (fname,scope,scopevalue,fvalue) 
								VALUES(?1,?2,?3,?4);",
                        )
                    };
                    conn.execute(
                        &cmd,
                        [
                            fname,
                            &field.scope.to_string(),
                            &field.scopevalue,
                            &field.value,
                        ],
                    )?;
                }
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            }
        }
        self.modified.clear();

        Ok(())
    }

    fn ensure_dbtable(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS 'appconfig'('scope' TEXT NOT NULL, 
				'scopevalue' TEXT, 'fname' TEXT NOT NULL UNIQUE, 'fvalue' TEXT);",
            [],
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;

    // Sets up the path to contain the database for the db-based tests
    fn setup_test(name: &str) -> PathBuf {
        if name.len() < 1 {
            panic!("Invalid name {} in setup_test", name);
        }
        let args: Vec<String> = env::args().collect();
        let test_path = PathBuf::from_str(&args[0]).unwrap();
        let mut test_path = test_path.parent().unwrap().to_path_buf();
        test_path.push("testfiles");
        test_path.push(name);

        if test_path.exists() {
            fs::remove_dir_all(&test_path).unwrap();
        }
        fs::create_dir_all(&test_path).unwrap();

        test_path
    }

    #[test]
    fn field_get_set() -> Result<(), MensagoError> {
        let testname = String::from("field_get_set");
        let mut c = Config::new("test");

        // Case #1: set_signature / get_signature
        c.set_signature("test-signature")?;
        if c.get_signature() != "test-signature" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: mismatch getting signature after set_signature",
                testname
            )));
        }

        // Case #2: get
        match c.get("application_signature") {
            Ok(v) => {
                if v != "test-signature" {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: mismatch getting signature via get()",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting signature via get(): {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #3: set
        c.set(
            "windows-path",
            ConfigScope::Platform,
            std::env::consts::OS,
            r"C:\Windows",
        )?;
        match c.get("windows-path") {
            Ok(v) => {
                if v != r"C:\Windows" {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: mismatch getting test field 'windows-path'",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting test field 'windows-path': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #4: get_int
        c.set(
            "some-number",
            ConfigScope::Architecture,
            std::env::consts::ARCH,
            r"101",
        )?;
        match c.get_int("some-number") {
            Ok(v) => {
                if v != 101 {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: mismatch getting int test field 'some-number'",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting test int field 'some-number': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #5: set_int
        c.set_int("some-number2", ConfigScope::Local, "", 999)?;
        match c.get("some-number2") {
            Ok(v) => {
                if v != "999" {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: mismatch setting int test field 'some-number2'",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error setting test int field 'some-number2': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #6: get_scope()
        match c.get_scope("some-number") {
            Ok(v) => {
                if v != (ConfigScope::Architecture, std::env::consts::ARCH) {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: mismatch getting scope for 'some-number'",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting scope for 'some-number': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #7: set_scope()
        match c.set_scope("some-number2", ConfigScope::Platform, std::env::consts::OS) {
            Ok(_) => {
                if c.get_scope("some-number2").unwrap()
                    != (ConfigScope::Platform, std::env::consts::OS)
                {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: mismatch setting scope for 'some-number2'",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error setting scope for 'some-number2': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }

    #[test]
    fn field_delete_fails() -> Result<(), MensagoError> {
        let testname = String::from("field_delete_fail_get_set");
        let mut c = Config::new("test");

        // Case #1: delete
        c.set_int("some-number", ConfigScope::Local, "", 999)?;
        match c.delete("some-number") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error deleting test int field 'some-number': {}",
                    testname,
                    e.to_string()
                )))
            }
        }
        match c.get_int("some-number") {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: delete() didn't actually delete test int field 'some-number'",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #2: try to delete a non-existent field
        match c.delete("some-number") {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: delete() passed deleting nonexistent field test",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #3: try to get() a nonexistent field
        match c.get("some-number") {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: get() passed getting nonexistent field test",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #4: try to get_scope() a nonexistent field
        match c.get_scope("some-number") {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: get_scope() passed getting nonexistent field test",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #5: try to set_scope() a nonexistent field
        match c.set_scope("some-number", ConfigScope::Platform, std::env::consts::OS) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: set_scope() passed getting nonexistent field test",
                    testname
                )))
            }
            Err(_) => (),
        }

        Ok(())
    }

    #[test]
    fn save_db() -> Result<(), MensagoError> {
        let testname = String::from("config_save_db");
        let test_path = setup_test(&testname);

        let mut c = Config::new("test");
        c.set("field1", ConfigScope::Global, "", "This is field 1's value")?;
        c.set_int("field2", ConfigScope::Platform, "windows", 10)?;

        if !c.is_modified() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect modification state",
                testname
            )));
        }

        let mut conn = DBConn::new();
        let mut dbpath = test_path.clone();
        dbpath.push("test.db");
        match conn.connect(&dbpath) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(String::from(
                    e.to_string(),
                )));
            }
        };

        // Case #1: Test save_db()
        match c.save_to_db(&mut conn) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error saving database: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        if c.is_modified() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect modification state after db save",
                testname
            )));
        }

        let rows = match conn.query(
            "SELECT scope,scopevalue,fvalue FROM appconfig WHERE fname=?1",
            ["field2"],
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting config info: {}",
                    testname,
                    e.to_string()
                )))
            }
        };
        if rows.len() != 1 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect number of rows found. Expected 1, found {}",
                testname,
                rows.len(),
            )));
        }
        if rows[0].len() != 3 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect number of row size. Expected 3, found {}",
                testname,
                rows[0].len(),
            )));
        }
        if rows[0][0].to_string() != "platform"
            || rows[0][1].to_string() != "windows"
            || rows[0][2].to_string() != "10"
        {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: data value mismatch",
                testname
            )));
        }

        // Case #2: Test update_db()
        c.set_signature("org.mensago.test-config_save_db")?;

        if !c.is_modified() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect modification state",
                testname
            )));
        }

        match c.update_db(&mut conn) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error updating database: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if c.is_modified() {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect modification state after db save",
                testname
            )));
        }

        let rows = match conn.query(
            "SELECT fvalue FROM appconfig WHERE fname='application_signature'",
            [],
        ) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error locating config field: {}",
                    testname,
                    e.to_string(),
                )));
            }
        };
        if rows.len() != 1 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect number of rows found checking update_db() results. Expected 1, found {}",
                testname,
                rows.len(),
            )));
        }
        if rows[0].len() != 1 {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: incorrect number of row size checking update_db() results. Expected 1, found {}",
                testname,
                rows[0].len(),
            )));
        }
        if rows[0][0].to_string() != "org.mensago.test-config_save_db" {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: signature mismatch for update_db() case",
                testname
            )));
        }

        Ok(())
    }

    #[test]
    fn load_db() -> Result<(), MensagoError> {
        let testname = String::from("config_load_db");
        let test_path = setup_test(&testname);

        let mut conn = DBConn::new();
        let mut dbpath = test_path.clone();
        dbpath.push("test.db");
        match conn.connect(&dbpath) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(String::from(
                    e.to_string(),
                )));
            }
        };

        conn.execute(
            "CREATE TABLE IF NOT EXISTS 'appconfig'('scope' TEXT NOT NULL, 
			'scopevalue' TEXT, 'fname' TEXT NOT NULL UNIQUE, 'fvalue' TEXT);",
            [],
        )?;
        conn.execute(
            "INSERT INTO appconfig(fname,scope,scopevalue,fvalue)
			VALUES('application_signature','global','','org.mensago.test-config_load_db')",
            [],
        )?;
        conn.execute(
            "INSERT INTO appconfig(fname,scope,scopevalue,fvalue)
			VALUES('field1','global','','This is field #1')",
            [],
        )?;
        conn.execute(
            "INSERT INTO appconfig(fname,scope,scopevalue,fvalue)
			VALUES('field2','platform','windows','10')",
            [],
        )?;

        let c = match Config::from_db(&mut conn) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error loading database: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        if c.get_int("field2").unwrap() != 10
            || c.get_scope("field2").unwrap() != (ConfigScope::Platform, "windows")
            || c.get_signature() != "org.mensago.test-config_load_db"
        {
            return Err(MensagoError::ErrProgramException(format!(
                "{}: row value mismatch",
                testname
            )));
        }

        Ok(())
    }
}
