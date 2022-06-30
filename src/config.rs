//! The config module is dedicated to storing application settings in the same database as the rest
//! of the user data.

use rusqlite;
use std::collections::HashMap;
use std::fmt;
use crate::base::*;

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
#[derive(Debug)]
pub struct Config {
	data: HashMap::<String, ConfigField>,
	modified: Vec::<String>,
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

	pub fn set_signature(&mut self, signature: &str) {
		self.signature = String::from(signature);
		self.set("application_signature", ConfigScope::Global, "", signature)
	}

	pub fn get_signature(&self) -> String {
		self.signature.clone()
	}

	/// Loads all fields from the database. NOTE: this call completely clears all data from the
	/// object prior to loading new values
	pub fn load_from_db(&mut self, conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// Regardless of the outcome, we need to have a nice clean start
		self.data.clear();
		self.modified.clear();
		
		self.ensure_dbtable(conn)?;

		// The table exists, so load up all values from it
		let mut stmt = conn.prepare("SELECT fname,scope,scopevalue,fvalue FROM appconfig")?;
		
		let mut rows = match stmt.query([]) {
			Ok(v) => v,
			Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
		};

		let mut option_row = match rows.next() {
			Ok(v) => v,
			Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
		};

		while option_row.is_some() {
			let row = option_row.unwrap();
			let fscope = match ConfigScope::from(&row.get::<usize,String>(1).unwrap()) {
				Some(v) => v,
				None => {
					return Err(MensagoError::ErrDatabaseException(
						format!("Bad scope {} for field {}",
							&row.get::<usize,String>(1).unwrap(),
							&row.get::<usize,String>(0).unwrap())
					))
				},
			};
			self.data.insert(String::from(&row.get::<usize,String>(0).unwrap()),
				ConfigField {
					scope: fscope,
					scopevalue: String::from(&row.get::<usize,String>(2).unwrap()),
					value: String::from(&row.get::<usize,String>(3).unwrap()),
				}
			);
			option_row = match rows.next() {
				Ok(v) => v,
				Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
			};
		}

		self.signature = match self.data.get("application_signature") {
			Some(v) => { v.value.clone() },
			None => { String::new() },
		};

		Ok(())
	}

	/// Saves all fields to the database. NOTE: this will completely clear the existing table of
	/// configuration in the database backend, so be sure you have everything the way you want it
	/// before calling this.
	pub fn save_to_db(&mut self, conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
		
		match conn.execute("DROP TABLE IF EXISTS appconfig", []) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())))
			}
		}

		self.ensure_dbtable(conn)?;
		
		// Save all values to the table. Unfortunately, this isn't as fast as it could be because
		// we can't validate the field values in any way, so we can't add all fields in batch.
		// Thankfully, we shouldn't be dealing with more than a few dozen to a few thousand
		// values.
		for (fname, field) in &self.data {
			match conn.execute(
				"INSERT INTO appconfig (fname,scope,scopevalue,fvalue) VALUES(?1,?2);", 
					[fname, &field.scope.to_string(), &field.scopevalue, &field.value]) {
				Ok(_) => (),
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())))
				}
			}
		}

		self.modified.clear();
		
		Ok(())
	}

	/// Saves modified values to the database. In general this should be faster than saving the
	/// entire object to the database.
	pub fn update_db(&mut self, conn: &rusqlite::Connection) -> Result<(), MensagoError> {

		// Check to see if the table exists in the database
		let mut stmt = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='appconfig'")?;
		
		match stmt.exists([]) {
			Ok(v) => {
				if !v { return self.save_to_db(&conn) }
			},
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		}

		// Save all values to the table
		for fname in &self.modified {

			let field = match self.data.get(fname) {
				Some(v) => v,
				None => {
					return Err(MensagoError::ErrDatabaseException(
						format!("BUG: modified item {} missing in database", fname)
					))
				}
			};

			let mut stmt = conn.prepare("SELECT fname FROM appconfig fname=?1")?;
		
			match stmt.exists([fname]) {
				Ok(v) => {
					if v {
						match conn.execute(
							"UPDATE appconfig SET scope=?2,scopevalue=?3,fvalue=?4 WHERE fname=?1;",
								[fname, &field.scope.to_string(), &field.scopevalue,
									&field.value]) {
							Ok(_) => (),
							Err(e) => {
								return Err(MensagoError::ErrDatabaseException(
									String::from(e.to_string())))
							}
						}
					} else {
						match conn.execute(
							"INSERT INTO appconfig (fname,scope,scopevalue,fvalue) 
								VALUES(?1,?2,?3,?4);", [fname, &field.scope.to_string(),
														&field.scopevalue, &field.value]) {
							Ok(_) => (),
							Err(e) => {
								return Err(MensagoError::ErrDatabaseException(
									String::from(e.to_string())))
							}
						}
					}
				},
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			}
		}

		self.modified.clear();
		
		Ok(())
	}

	/// Sets a field value. Note that setting a value requires deciding what scope to which the
	/// field belongs and setting it accordingly. See documentation on the ConfigScope structure
	/// for more information.
	pub fn set(&mut self, field: &str, scope: ConfigScope, scopevalue: &str, value: &str) {
		self.data.insert(String::from(field),
			ConfigField {
				scope: scope,
				scopevalue: String::from(scopevalue),
				value: String::from(value)
			});
		self.modified.push(String::from(field))
	}

	/// Gets a field value
	pub fn get(&self, field: &str) -> Result<String, MensagoError> {
		match self.data.get(field) {
			Some(v) => Ok(v.value.clone()),
			None => { Err(MensagoError::ErrNotFound) }
		}
	}

	/// Returns true if the table has a specific field
	pub fn has(&self, field: &str) -> bool {
		self.data.get(field).is_some()
	}

	/// Sets an integer field value. Note that setting a value requires deciding what scope to
	/// which the field belongs and setting it accordingly. See documentation on the ConfigScope
	/// structure for more information.
	pub fn set_int(&mut self, field: &str, scope: ConfigScope, scopevalue: &str, value: isize) {
		self.data.insert(String::from(field),
			ConfigField {
				scope: scope,
				scopevalue: String::from(scopevalue),
				value: value.to_string(),
			});
		self.modified.push(String::from(field))
	}

	/// Gets a field value.
	pub fn get_int(&self, field: &str) -> Result<isize, MensagoError> {

		let field = match self.data.get(field) {
			Some(v) => v,
			None => { return Err(MensagoError::ErrNotFound) }
		};

		match field.value.parse::<isize>() {
			Ok(v) => Ok(v),
			Err(_) => { Err(MensagoError::ErrTypeMismatch) },
		}
	}

	fn ensure_dbtable(&self, conn: &rusqlite::Connection) -> Result<(), MensagoError> {

		let mut stmt = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='appconfig'")?;
		
		match stmt.exists([]) {
			Ok(v) => {
				if v {
					match conn.execute(
						"CREATE TABLE 'appconfig'('scope' TEXT NOT NULL, 'scopevalue' TEXT,
							'fname' TEXT NOT NULL UNIQUE, 'fvalue' TEXT);",
							[]) {
						Ok(_) => (),
						Err(e) => {
							return Err(MensagoError::ErrDatabaseException(
								String::from(e.to_string())))
						}
					}
				}
			},
			Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn field_ops() -> Result<(), MensagoError> {

		let testname = String::from("field_ops");
		let mut c = Config::new("test");
		
		// Case #1: set_signature / get_signature
		c.set_signature("test-signature");
		if c.get_signature() != "test-signature" {
			return Err(MensagoError::ErrProgramException(
				format!("{}: mismatch getting signature after set_signature", testname)))
		}

		// Case #2: get
		match c.get("application_signature"){
			Ok(v) => {
				if v != "test-signature" {
					return Err(MensagoError::ErrProgramException(
						format!("{}: mismatch getting signature via get()", testname)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting signature via get(): {}", testname, e.to_string())))
			}
		}

		// Case #3: set
		c.set("windows-path", ConfigScope::Platform, std::env::consts::OS, r"C:\Windows");
		match c.get("windows-path"){
			Ok(v) => {
				if v != r"C:\Windows" {
					return Err(MensagoError::ErrProgramException(
						format!("{}: mismatch getting test field 'windows-path'", testname)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting test field 'windows-path': {}", testname,
						e.to_string())))
			}
		}

		// Case #4: get_int
		c.set("some-number", ConfigScope::Architecture, std::env::consts::ARCH, r"101");
		match c.get_int("some-number"){
			Ok(v) => {
				if v != 101 {
					return Err(MensagoError::ErrProgramException(
						format!("{}: mismatch getting int test field 'some-number'", testname)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error getting test int field 'some-number': {}", testname,
						e.to_string())))
			}
		}

		// Case #5: set_int
		c.set_int("some-number2", ConfigScope::Local, "", 999);
		match c.get("some-number2"){
			Ok(v) => {
				if v != "999" {
					return Err(MensagoError::ErrProgramException(
						format!("{}: mismatch setting int test field 'some-number2'", testname)))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("{}: error setting test int field 'some-number2': {}", testname,
						e.to_string())))
			}
		}

		Ok(())
	}

}

// TODO: Finish testing config module
