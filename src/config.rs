//! The config module is dedicated to storing application settings in the same database as the rest
//! of the user data.

use rusqlite;
use std::collections::HashMap;
use crate::base::*;

/// The AppConfig class is just a hash map for holding strings containing app configuration
/// information with some methods to make usage easier
#[derive(Debug)]
pub struct Config {
	pub data: HashMap::<&'static str, String>,
}

impl Config {

	/// Creates a new empty AppConfig instance
	pub fn new() -> Config {
		Config {
			data: HashMap::<&'static str, String>::new(),
		}
	}

	/// Loads all fields from the database
	pub fn load_from_db(&mut self, _conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// TODO: Implement AppConfig::load_from_db()
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

