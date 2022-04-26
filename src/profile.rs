use rusqlite;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use crate::base::*;
use crate::types::*;
use crate::workspace::*;

// String for initializing a new profile database
static DB_SETUP_COMMANDS: &str = "
	CREATE TABLE workspaces (
		'wid' TEXT NOT NULL UNIQUE,
		'userid' TEXT,
		'domain' TEXT,
		'password' TEXT,
		'pwhashtype' TEXT,
		'type' TEXT
	);
	CREATE table 'folders'(
		'fid' TEXT NOT NULL UNIQUE,
		'address' TEXT NOT NULL,
		'keyid' TEXT NOT NULL,
		'path' TEXT NOT NULL,
		'name' TEXT NOT NULL,
		'permissions' TEXT NOT NULL
	);
	CREATE table 'sessions'(
		'address' TEXT NOT NULL,
		'devid' TEXT NOT NULL,
		'devname' TEXT NOT NULL,
		'public_key' TEXT NOT NULL,
		'private_key' TEXT NOT NULL,
		'os' TEXT NOT NULL
	);
	CREATE table 'keys'(
		'keyid' TEXT NOT NULL UNIQUE,
		'address' TEXT NOT NULL,
		'type' TEXT NOT NULL,
		'category' TEXT NOT NULL,
		'private' TEXT NOT NULL,
		'public' TEXT,
		'timestamp' TEXT NOT NULL
	);
	CREATE table 'keycards'(
		'rowid' INTEGER PRIMARY KEY AUTOINCREMENT,
		'owner' TEXT NOT NULL,
		'index' INTEGER,
		'type' TEXT NOT NULL,
		'entry' BLOB NOT NULL,
		'textentry' TEXT NOT NULL,
		'hash' TEXT NOT NULL,
		'expires' TEXT NOT NULL,
		'timestamp' TEXT NOT NULL
	);
	CREATE table 'messages'(
		'id' TEXT NOT NULL UNIQUE,
		'from'  TEXT NOT NULL,
		'address' TEXT NOT NULL,
		'cc'  TEXT,
		'bcc' TEXT,
		'date' TEXT NOT NULL,
		'thread_id' TEXT NOT NULL,
		'subject' TEXT,
		'body' TEXT,
		'attachments' TEXT
	);
	CREATE TABLE 'contactinfo' (
		'id' TEXT NOT NULL,
		'fieldname' TEXT NOT NULL,
		'fieldvalue' TEXT,
		'contactgroup' TEXT
	);
	CREATE TABLE 'userinfo' (
		'fieldname' TEXT NOT NULL,
		'fieldvalue' TEXT
	);
	CREATE TABLE 'annotations' (
		'id' TEXT NOT NULL,
		'fieldname' TEXT NOT NULL,
		'fieldvalue' TEXT,
		'contactgroup' TEXT
	);
	CREATE TABLE 'updates' (
		'id' TEXT NOT NULL UNIQUE,
		'type' TEXT NOT NULL,
		'data' TEXT NOT NULL,
		'time' TEXT NOT NULL
	);''','''
	CREATE TABLE 'photos' (
		'id' TEXT NOT NULL,
		'type' TEXT NOT NULL,
		'photodata' BLOB,
		'isannotation' TEXT NOT NULL,
		'contactgroup' TEXT
	);
	CREATE TABLE 'notes' (
		'id'	TEXT NOT NULL UNIQUE,
		'address' TEXT,
		'title'	TEXT,
		'body'	TEXT,
		'notebook'	TEXT,
		'tags'	TEXT,
		'created'	TEXT NOT NULL,
		'updated'	TEXT,
		'attachments'	TEXT
	);
	CREATE TABLE 'files' (
		'id'	TEXT NOT NULL UNIQUE,
		'name'	TEXT NOT NULL,
		'type'	TEXT NOT NULL,
		'path'	TEXT NOT NULL
	);";

/// The Profile type is the client's entry point to interacting with storage. One major point to
/// note is that it owns the database instance. Unless you are specifically managing profiles, you
/// will probably load the default profile using ProfileManager and use the profile instance
/// to get to the database handle.
#[derive(Debug)]
pub struct Profile {
	name: String,
	path: PathBuf,
	is_default: bool,
	uid: Option<UserID>,
	wid: Option<RandomID>,
	domain: Option<Domain>,
	devid: Option<RandomID>
}

impl Profile {

	/// Creates a new profile from a specified path
	pub fn new(profpath: &Path) -> Result<Profile, MensagoError> {

		let mut profname = match profpath.to_str() {
			Some(v) => v,
			None =>  { return Err(MensagoError::ErrBadValue) },
		};
		if profname.len() == 0 {
			return Err(MensagoError::ErrEmptyData);
		}
		profname = match profpath.parent() {
			Some(v) => v.to_str().unwrap(),
			None => { return Err(MensagoError::ErrBadValue) },
		};
		
		let mut profile = Profile{
			name: String::from(profname),
			path: PathBuf::from(profpath),
			is_default: false,
			uid: None,
			wid: None,
			domain: None,
			devid: None,
		};
		
		let mut defpath = profile.path.to_path_buf();
		defpath.push("default.txt");
		if defpath.exists() {
			profile.is_default = true;
		}

		match profile.load_config() {
			Ok(_) => {
				if profile.devid == None {
					profile.devid = Some(RandomID::generate());
				}
			},
			Err(_) => {
				if profile.devid == None {
					profile.devid = Some(RandomID::generate());
				}
				profile.save_config()?
			}
		}
		
		Ok(profile)
	}

	/// Connects the profile to its associated database, initializing it if necessary.
	pub fn activate(&mut self) -> Result<(), MensagoError> {

		let mut tempdir = self.path.clone();
		tempdir.push("temp");
		if !tempdir.exists() {
			fs::create_dir_all(tempdir)?;
		}

		let mut dbpath = self.path.clone();
		dbpath.push("storage.db");
		if dbpath.exists() {

			let db = rusqlite::Connection::open(dbpath)?;

			// TODO: load app config from database

			db.close().expect("BUG: Profile.activate(): error closing database");
			return Ok(());
		}

		self.reset_db()
	}

	/// Loads the config file for the profile
	pub fn load_config(&mut self) -> Result<(), MensagoError> {

		// TODO: Implement Profile::load_config()

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Saves the config file for the profile
	pub fn save_config(&mut self) -> Result<(), MensagoError> {

		// TODO: Implement Profile::save_config()

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Sets the profile's internal flag that it is the default profile
	pub fn set_default(&mut self, is_default: bool) -> Result<(), MensagoError> {

		let mut dbpath = self.path.clone();
		dbpath.push("default.txt");
		if is_default {
			if !dbpath.exists() {
				let _handle = fs::File::create(dbpath)?;
			}
		} else {
			if dbpath.exists() {
				fs::remove_file(dbpath)?;
			}
		}

		self.is_default = is_default;

		Ok(())
	}

	/// Returns true if the profile has been told it's the default
	pub fn is_default(&self) -> bool {
		return self.is_default;
	}

	/// Returns the identity workspace address for the profile
	pub fn get_identity(&mut self) -> Result<MAddress,MensagoError> {

		if self.uid.is_some() && self.domain.is_some() {
			return Ok(MAddress::from_parts(self.uid.as_ref().unwrap(),
				self.domain.as_ref().unwrap()))
			
		}

		if self.wid.is_some() && self.domain.is_some() {
			return Ok(MAddress::from_parts(&UserID::from_wid(self.wid.as_ref().unwrap()),
				self.domain.as_ref().unwrap()))
			
		}

		// We got this far, which means we need to get the info from the profile database
		{
			let conn = self.open_db()?;

			let mut stmt = match conn
				.prepare("SELECT wid,domain,userid FROM workspaces WHERE type = 'identity'") {
					Ok(v) => v,
					Err(e) => {
						return Err(MensagoError::ErrDatabaseException(e.to_string()))
					}
				};
			
			// Queries with rusqlite are extremely ugly because the results wrapped several layers
			// deep. The query() call returns a Result containing a Rows() structure. If we get an
			// error here, there was a problem either with the query or the database.
			let mut rows = match stmt.query([]) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};

			// The Rows::next() call returns Result<Some<Result<Row>>>. Seriously. The possible
			// return values are:
			//
			// Err() -> an error occurred getting the next row
			// Ok(Some(Row)) -> another row was returned
			// Ok(None) -> all results have been returned
			
			let option_row = match rows.next() {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(e.to_string()))
				}
			};

			// We've actually removed enough layers to get an idea of if we actually were successful
			// in finding the identity info.
			if option_row.is_none() {
				// We have a problem: no identity entry in the database for the workspace.
				return Err(MensagoError::ErrDatabaseException(
						String::from("Database has no identity entry in 'workspaces'")));
			}

			let row = option_row.unwrap();
			if self.wid.is_none() {
				self.wid = RandomID::from_str(&row.get::<usize,String>(0).unwrap());
			}
			if self.domain.is_none() {
				self.domain = Domain::from_str(&row.get::<usize,String>(1).unwrap());
			}
			if self.uid.is_none() {
				self.uid = UserID::from_str(&row.get::<usize,String>(3).unwrap());
			}

			// Connection to the database will be closed when the connection object is dropped
		}

		if self.uid.is_some() && self.domain.is_some() {
			return Ok(MAddress::from_parts(self.uid.as_ref().unwrap(),
				self.domain.as_ref().unwrap()))
			
		}

		if self.wid.is_some() && self.domain.is_some() {
			return Ok(MAddress::from_parts(&UserID::from_wid(self.wid.as_ref().unwrap()),
				self.domain.as_ref().unwrap()))
			
		}

		return Err(MensagoError::ErrProgramException(
			String::from("BUG: Malformed MAddress returned from get_identity")))
	}

	/// Assigns an identity workspace to the profile
	pub fn set_identity(&self, w: Workspace) -> Result<(),MensagoError> {

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Reinitializes the profile's database to empty
	pub fn reset_db(&self) -> Result<(),MensagoError> {

		let mut dbpath = self.path.clone();
		dbpath.push("storage.db");

		if dbpath.exists() {
			fs::remove_file(&dbpath)?;
		}

		{
			let conn = match rusqlite::Connection::open(&dbpath) {
				Ok(v) => v,
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			};

			match conn.execute(DB_SETUP_COMMANDS, []) {
				Ok(_) => { /* do nothing. YAY */ },
				Err(e) => {
					return Err(MensagoError::ErrDatabaseException(String::from(e.to_string())));
				}
			}
		}

		Ok(())
	}
	
	/// Resolves a Mensago address to its corresponding workspace ID
	pub fn resolve_address(&self, a: MAddress) -> Result<RandomID,MensagoError> {

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Private function to make code that deals with the database easier. It also ensures that
	/// an error is returned if the database doesn't exist.
	fn open_db(&self) -> Result<rusqlite::Connection, rusqlite::Error> {
		
		let mut dbpath = self.path.clone();
		dbpath.push("storage.db");
		rusqlite::Connection::open_with_flags(dbpath, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
	}
}

/// The ProfileManager is an type which creates and deletes user on-disk profiles and otherwise
/// provides access to them.
#[derive(Debug)]
pub struct ProfileManager {
	profiles: Vec<Profile>,
	profile_folder: PathBuf,
	active_index: isize,
	default_index: isize,
	profile_id: String,
}

impl ProfileManager {

	/// Creates a new, uninitialized ProfileManager
	pub fn new(profile_path: &PathBuf) -> ProfileManager {

		ProfileManager {
			profiles: Vec::<Profile>::new(),
			profile_folder: profile_path.clone(),
			active_index: -1,
			default_index: -1,
			profile_id: String::from(""),
		}
	}

	/// Sets the named profile as active.
	pub fn activate_profile(&mut self, name: &str) -> Result<&Profile, MensagoError> {

		if name.len() == 0 {
			return Err(MensagoError::ErrEmptyData);
		}

		let name_squashed = name.to_lowercase();
		let active_index = match self.index_for_name(&name_squashed) {
			x if x >= 0 => x,
			_ => return Err(MensagoError::ErrNotFound)
		};

		if active_index >= 0 {
			self.active_index = -1;
		}

		self.profile_id = name_squashed;
		self.active_index = active_index;
		self.profiles[active_index as usize].activate()?;

		// Force loading of basic identity info if it hasn't already been done
		self.profiles[active_index as usize].get_identity()?;

		return Ok(&self.profiles[active_index as usize]);
	}

	/// Returns the number of profiles in the user's profile folder
	pub fn count_profiles(&self) -> usize {
		self.profiles.len()
	}

	/// Creates a profile of the given name in the user's profile folder. Care should be used with
	/// spaces and special characters, as the name will be used as the profile's directory name in the
	/// filesystem. The name 'default' is reserved and may not be used. Note that the profile name is
	/// not case-sensitive and as such capitalization will be squashed when passed to this function.
	pub fn create_profile(&mut self, name: &str) -> Result<&Profile, MensagoError> {

		if name.len() == 0 {
			return Err(MensagoError::ErrEmptyData)
		}

		let name_squashed = name.to_lowercase();
		if name_squashed == "default" {
			return Err(MensagoError::ErrReserved)
		}

		if self.index_for_name(&name_squashed) >= 0 {
			return Err(MensagoError::ErrExists);
		}

		let mut new_profile_path = PathBuf::from(&self.profile_folder);
		new_profile_path.push(&name_squashed);
		match fs::DirBuilder::new().recursive(true).create(new_profile_path.as_path()) {
			Err(_) => return Err(MensagoError::ErrFilesytemError),
			Ok(_) => { /* do nothing */ }
		}

		let mut profile = Profile {
			name: String::from(name_squashed),
			path: new_profile_path,
			is_default: false,
			uid: None,
			wid: None,
			domain: None,
			devid: None
		};

		if self.count_profiles() == 0 {
			profile.is_default = true;
			self.default_index = 1;
		}
		
		self.profiles.push(profile);

		Ok(self.profiles.get(self.profiles.len()-1).unwrap())
	}

	/// Deletes the named profile and all files on disk contained in it.
	pub fn delete_profile(&mut self, name: &str) -> Result<(), MensagoError> {

		if name.len() == 0 {
			return Err(MensagoError::ErrEmptyData)
		}

		let name_squashed = name.to_lowercase();
		if name_squashed == "default" {
			return Err(MensagoError::ErrReserved)
		}

		let pindex = match self.index_for_name(&name_squashed) {
			v if v >= 0 => v,
			_ => return Err(MensagoError::ErrNotFound),
		};

		let profile = self.profiles.remove(pindex as usize);
		if Path::new(profile.path.as_path()).exists() {
			fs::remove_dir_all(profile.path.as_path())?
		}

		if profile.is_default() && self.profiles.len() > 0 {
			match self.profiles[0].set_default(true) {
				Ok(_) => { /* Do nothing */ },
				Err(e) => return Err(e)
			}
		}

		Ok(())
	}

	/// Returns the active profile
	pub fn get_active_profile(&self) -> Option<&Profile> {

		match self.active_index {
			v if v >=0 => {
				self.profiles.get(self.active_index as usize)
			},
			_ => {
				None
			},
		}
	}

	/// Returns the default profile
	pub fn get_default_profile(&self) -> Option<&Profile> {

		match self.default_index {
			v if v >=0 => {
				self.profiles.get(self.default_index as usize)
			},
			_ => {
				None
			},
		}
	}

	/// Returns a Vec of all available profiles
	pub fn get_profiles(&self) -> &Vec<Profile> {
		&self.profiles
	}

	/// Loads all profiles under the specified path. If None is passed to the function, the profile
	/// manager will look in ~/.config/mensago on POSIX platforms and %LOCALAPPDATA%\mensago on
	/// Windows. It returns None on success or a String error.
	pub fn load_profiles(&mut self, profile_path: Option<&PathBuf>) -> Result<(), MensagoError> {
		
		self.active_index = -1;

		self.profile_folder = match profile_path {
			Some(s) => PathBuf::from(s),
			None => {
				if cfg!(windows) {
					let mut out = PathBuf::new();
					out.push(&env::var("LOCALAPPDATA").expect("BUG: error getting LOCALAPPDATA"));
					out.push("mensago");
					out
				} else {
					let mut out = PathBuf::new();
					out.push(&env::var("LOCALAPPDATA").expect("BUG: error getting LOCALAPPDATA"));
					out.push("mensago");
					out
				}
			},
		};

		if !self.profile_folder.exists() {
			fs::create_dir_all(self.profile_folder.as_path())?;
		}

		self.profiles.clear();
		for item in fs::read_dir(self.profile_folder.as_path())? {
			let entry = item?;
			let itempath  = entry.path();
			if !itempath.is_dir() {
				continue;
			}

			let mut profile = Profile::new(&itempath)?;
			if profile.is_default() {
				if self.default_index >= 0 {
					// If we have more than one profile marked as default, the one in the list
					// with the lower index retains that status
					profile.set_default(false)?;
					self.profiles.push(profile);
				} else {
					self.profiles.push(profile);
					self.default_index = (self.profiles.len()-1) as isize;
				}
			}
		}

		// If we've gotten through the entire loading process and we haven't got a single profile
		// loaded, then create one
		if self.profiles.len() == 0 {
			match self.create_profile("primary") {
				Ok(_) => {
					self.set_default_profile("primary")?;
				},
				Err(e) => {
					return Err(e);
				}
			}
		}
		
		let default_name = match self.get_default_profile() {
			Some(v) => String::from(&v.name),
			None => {
				return Err(MensagoError::ErrProgramException( 
					String::from("BUG: Couldn't find default profile in load_profiles()")));
			},
		};

		self.activate_profile(&default_name)?;
		
		Ok(())
	}

	/// Renames the profile from the old name to the new one
	pub fn rename_profile(&mut self, oldname: &str, newname: &str) -> Result<(), MensagoError> {

		if oldname.len() == 0 || newname.len() == 0 {
			return Err(MensagoError::ErrEmptyData)
		}

		let old_squashed = oldname.to_lowercase();
		let new_squashed = newname.to_lowercase();

		let index = match self.index_for_name(&old_squashed) {
			v if v >= 0 => v,
			_ => return Err(MensagoError::ErrNotFound)
		};

		if self.index_for_name(&new_squashed) >= 0 {
			return Err(MensagoError::ErrExists)
		}

		let oldpath = self.profiles[index as usize].path.clone();
		let mut newpath = oldpath.parent().unwrap().to_path_buf();
		newpath.push(&new_squashed);

		fs::rename(&oldpath, &newpath)?;

		self.profiles[index as usize].name = new_squashed;
		self.profiles[index as usize].path = newpath;

		if index == self.active_index {
			self.profiles[index as usize].activate()?;
		}

		Ok(())
	}

	/// Sets the default profile
	pub fn set_default_profile(&mut self, name: &str) -> Result<(), MensagoError> {

		if name.len() == 0 {
			return Err(MensagoError::ErrEmptyData)
		}

		if self.profiles.len() == 1 {
			if !self.profiles[0].is_default() {
				self.profiles[0].set_default(true)?;
			}

			return Ok(());
		}

		let mut oldindex: isize = -1;
		for i in 0..self.profiles.len() {
			if self.profiles[i].is_default() {
				oldindex = i as isize;
				break
			}
		}

		let name_squashed = name.to_lowercase();
		let newindex = match self.index_for_name(&name_squashed) {
			x if x >= 0 => x,
			_ => return Err(MensagoError::ErrNotFound)
		};

		if oldindex <= 0 {
			if name_squashed == self.profiles[oldindex as usize].name {
				return Ok(())
			}
			self.profiles[oldindex as usize].set_default(false)?;
		}

		self.profiles[newindex as usize].set_default(true)
	}

	/// Obtains the index for a profile with the supplied name. Returns None on error.
	fn index_for_name(&self, name: &str) -> isize {
		
		if name.len() == 0 {
			return -1
		}

		for i in 0..self.profiles.len() {
			let p = match self.profiles.get(i) {
				Some(v) => v,
				None => { return -1; },
			};
			
			if p.name == name {
				return i as isize;
			}
		}

		-1
	}	
}

#[cfg(test)]
mod tests {
	use crate::*;


}