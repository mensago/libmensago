use std::path::{PathBuf};
use rusqlite;
use crate::base::*;
use crate::types::*;

pub fn get_credentials(dbpath: PathBuf, waddr: WAddress) -> Result<PassHash, MensagoError> {
	
	// TODO: implement auth.get_credentials()

	Err(MensagoError::ErrUnimplemented)
}
