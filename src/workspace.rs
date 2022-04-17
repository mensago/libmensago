use std::path::PathBuf;
use crate::types::*;

#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct Workspace {
	// db: rusqlite::Connection,
	path: PathBuf,
	uid: UserID,
	wid: RandomID,
	domain: Domain,
	_type: String,
	pw: String,
}
