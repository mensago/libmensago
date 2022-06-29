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

/// The Config class is just a hash map for holding strings containing app configuration
/// information with some methods to make usage easier
#[derive(Debug)]
pub struct Config {
	data: HashMap::<String, String>,
	modified: Vec::<String>,
}

impl Config {

	/// Creates a new empty AppConfig instance
	pub fn new() -> Config {
		Config {
			data: HashMap::<String, String>::new(),
			modified: Vec::<String>::new(),
		}
	}

	/// Loads all fields from the database. NOTE: this call completely clears all data from the
	/// object prior to loading new values
	pub fn load_from_db(&mut self, conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// Regardless of the outcome, we need to have a nice clean start
		self.data.clear();
		self.modified.clear();
		
		// Check to see if the table exists in the database

		let mut stmt = conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='appconfig'")?;
		
		// If the row is None, then the table doesn't exist. Create it and move on.
		match stmt.exists([]) {
			Ok(v) => {
				if v {
					match conn.execute(
						"CREATE TABLE 'appconfig'('fname' TEXT NOT NULL UNIQUE, 'fvalue' TEXT);",
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

		// The table exists, so load up all values from it
		let mut stmt = conn.prepare("SELECT fname,fvalue FROM appconfig")?;
		
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
			self.data.insert(String::from(&row.get::<usize,String>(0).unwrap()),
				String::from(&row.get::<usize,String>(1).unwrap()));
			option_row = match rows.next() {
				Ok(v) => v,
				Err(e) => { return Err(MensagoError::ErrDatabaseException(e.to_string())) }
			};
		}

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

		match conn.execute(
			"CREATE TABLE 'appconfig'('fname' TEXT NOT NULL UNIQUE, 'fvalue' TEXT);", []) {
			Ok(_) => (),
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())))
			}
		}

		// Save all values to the table. Unfortunately, this isn't as fast as it could be because
		// we can't validate the field values in any way, so we can't add all fields in batch.
		// Thankfully, we shouldn't be dealing with more than a few dozen to a few thousand
		// values.
		for (fname,fvalue) in &self.data {
			match conn.execute(
				"INSERT INTO appconfig (fname,fvalue) VALUES(?1,?2);", [fname, fvalue]) {
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

			let fvalue = match self.data.get(fname) {
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
							"UPDATE appconfig SET fvalue=?2 WHERE fname=?1;", [fname, fvalue]) {
							Ok(_) => (),
							Err(e) => {
								return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())))
							}
						}
					} else {
						match conn.execute(
							"INSERT INTO appconfig (fname,fvalue) VALUES(?1,?2);", [fname, fvalue]) {
							Ok(_) => (),
							Err(e) => {
								return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())))
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

	/// Sets a field value
	pub fn set(&mut self, field: &str, value: &str) {
		self.data.insert(String::from(field), String::from(value));
		self.modified.push(String::from(field))
	}

	/// Gets a field value
	pub fn get(&self, field: &str) -> Result<String, MensagoError> {
		match self.data.get(field) {
			Some(v) => Ok(v.clone()),
			None => { Err(MensagoError::ErrNotFound) }
		}
	}

	/// Returns true if the table has a specific field
	pub fn has(&self, field: &str) -> bool {
		self.data.get(field).is_some()
	}

	/// Sets an integer field value
	pub fn set_int(&mut self, field: &str, value: isize) {
		self.data.insert(String::from(field), value.to_string());
		self.modified.push(String::from(field))
	}

	/// Gets a field value
	pub fn get_int(&self, field: &str) -> Result<isize, MensagoError> {

		let s = match self.data.get(field) {
			Some(v) => v,
			None => { return Err(MensagoError::ErrNotFound) }
		};

		match s.parse::<isize>() {
			Ok(v) => Ok(v),
			Err(_) => { Err(MensagoError::ErrTypeMismatch) },
		}
	}
}

// TODO: Add tests to config module
