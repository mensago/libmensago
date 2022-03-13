use crate::types::*;

/// The Profile type is the client's entry point to interacting with storage. One major point to
/// note is that it owns the database instance. Unless you are specifically managing profiles, you
/// will probably load the default profile using ProfileManager and use the profile instance
/// to get to the database handle.
#[derive(Debug)]
pub struct Profile {
	name: String,
	path: String,
	is_default: bool,
	uid: UserID,
	wid: RandomID,
	// db: rusqlite::Connection,
	domain: Domain,
	devid: RandomID
}

impl Profile {

}

/// The ProfileManager is a singleton object which creates and deletes user on-disk profiles and
/// otherwise provides access to them.
#[derive(Debug)]
pub struct ProfileManager {
	profiles: Vec<Profile>,
	default_name: String,
	active_index: u16
}

impl ProfileManager {

}