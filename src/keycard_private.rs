use chrono::prelude::*;
use chrono::Duration;
use crate::base::*;

// Takes a string containing an index and increments the value inside it, e.g. "21" -> "22"
pub fn increment_index_string(s: &str) -> Result<String, MensagoError> {

	let mut val: u32 = match s.parse::<u32>() {
		Ok(v) => v,
		Err(_) => { return Err(MensagoError::ErrBadValue) },
	};

	val += 1;
	Ok(val.to_string())
}

pub fn get_offset_date(d: Duration) -> Option<String> {

	let offset_date = Utc::now().date().naive_utc()
		.checked_add_signed(d)
		.expect("Unable to create date 365 days from now");

	Some(offset_date.format("%Y%m%d").to_string())
}

