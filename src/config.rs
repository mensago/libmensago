//! The config module is dedicated to storing application settings in the same database as the rest
//! of the user data.

use rusqlite;
use std::collections::HashMap;
use crate::base::*;

/// The AppConfig class is just a hash map for holding strings containing app configuration
/// information with some methods to make usage easier
#[derive(Debug)]
pub struct AppConfig {
	pub data: HashMap::<&'static str, String>,
}

impl AppConfig {

	/// Loads all fields from the database
	pub fn load_from_db(_conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// TODO: Implement AppConfig::load_from_db()
		Ok(())
	}

	/// Saves all fields to the database
	pub fn save_to_db(_conn: &rusqlite::Connection)
	-> Result<(), MensagoError> {
	
		// TODO: Implement AppConfig::save_to_db()
		Ok(())
	}

	/// Sets a field value
	pub fn set(_field: &str, _value: &str) -> Result<(), MensagoError> {

		// TODO: Implement AppConfig::set()
		Ok(())
	}

	/// Gets a field value
	pub fn get(_field: &str) -> Result<String, MensagoError> {

		// TODO: Implement AppConfig::get()
		Ok(String::new())
	}

	/// Sets an integer field value
	pub fn set_int(_field: &str, _value: isize) -> Result<(), MensagoError> {

		// TODO: Implement AppConfig::set_int()
		Ok(())
	}

	/// Gets a field value
	pub fn get_int(_field: &str) -> Result<isize, MensagoError> {

		// TODO: Implement AppConfig::get_int()
		Ok(0)
	}
}

