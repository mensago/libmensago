//! The config module is dedicated to storing application settings in the same database as the rest
//! of the user data.

use rusqlite;
use std::collections::HashMap;
use crate::base::*;

/// The AppConfig class is just a hash map for holding strings containing app configuration
/// information with some methods to make usage easier
#[derive(Debug)]
pub struct Config {
	pub data: HashMap::<String, String>,
}

impl Config {

	/// Creates a new empty AppConfig instance
	pub fn new() -> Config {
		Config {
			data: HashMap::<String, String>::new(),
		}
	}

	/// Loads all fields from the database. NOTE: this call completely clears all data from the
	/// object prior to loading new values
	pub fn load_from_db(&mut self, conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// Regardless of the outcome, we need to have a nice clean start
		self.data = HashMap::<String, String>::new();
		
		// Check to see if the table exists in the database

		let mut stmt = match conn
			.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='appconfig'") {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		
		let mut rows = match stmt.query([]) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

		let option_row = match rows.next() {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

		// If the row is None, then the table doesn't exist. Create it and move on.
		if option_row.is_none() {
			return match conn.execute(
				"CREATE TABLE 'appconfig'('fname' TEXT NOT NULL UNIQUE, 'fvalue' TEXT);", []) {
				Ok(_) => Ok(()),
				Err(e) => {
					Err(MensagoError::ErrDatabaseException(String::from(e.to_string())))
				}
			}
		}

		// The table exists, so load up all values from it
		let mut stmt = match conn.prepare("SELECT fname,fvalue FROM appconfig") {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};
		
		let mut rows = match stmt.query([]) {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

		let mut option_row = match rows.next() {
			Ok(v) => v,
			Err(e) => {
				return Err(MensagoError::ErrDatabaseException(e.to_string()))
			}
		};

		while option_row.is_some() {
			let row = option_row.unwrap();
			self.data.insert(String::from(&row.get::<usize,String>(0).unwrap()),
				String::from(&row.get::<usize,String>(1).unwrap()));
			option_row = match rows.next() {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};
		}

		Ok(())
	}

	/// Saves all fields to the database
	pub fn save_to_db(&self, _conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// TODO: Implement AppConfig::save_to_db()
		Ok(())
	}

	/// Sets a field value
	pub fn set(&mut self, _field: &str, _value: &str) -> Result<(), MensagoError> {

		// TODO: Implement AppConfig::set()
		Ok(())
	}

	/// Gets a field value
	pub fn get(&self, _field: &str) -> Result<String, MensagoError> {

		// TODO: Implement AppConfig::get()
		Ok(String::new())
	}

	/// Sets an integer field value
	pub fn set_int(&mut self, _field: &str, _value: isize) -> Result<(), MensagoError> {

		// TODO: Implement AppConfig::set_int()
		Ok(())
	}

	/// Gets a field value
	pub fn get_int(&self, _field: &str) -> Result<isize, MensagoError> {

		// TODO: Implement AppConfig::get_int()
		Ok(0)
	}
}

