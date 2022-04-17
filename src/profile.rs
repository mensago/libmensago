use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use crate::base::*;
use crate::types::*;


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
	// db: rusqlite::Connection,
	domain: Option<Domain>,
	devid: Option<RandomID>
}

impl Profile {

	/// Creates a new profile from a specified path
	pub fn new(profpath: &Path) -> Profile {

		// TODO: Finish immplementing Profile::new()

		Profile{
			name: String::from(""),
			path: PathBuf::from(profpath),
			is_default: false,
			uid: None,
			wid: None,
			domain: None,
			devid: None,
		}
	}

	/// Sets the profile's internal flag that it is the default profile
	pub fn set_default(&mut self, is_default: bool) -> Option<String> {

		return Some(String::from("Unimplemented"))
	}

	/// Returns true if the profile has been told it's the default
	pub fn is_default(&self) -> bool {
		return self.is_default;
	}

}

/// The ProfileManager is an type which creates and deletes user on-disk profiles and otherwise
/// provides access to them.
#[derive(Debug)]
pub struct ProfileManager {
	profiles: Vec<Profile>,
	profile_folder: PathBuf,
	active_index: Option<usize>,
	default_index: Option<usize>
}

impl ProfileManager {

	pub fn activate_profile(&mut self, name: &str) -> Option<&'static Profile> {

		// TODO: Implement activate_profile()

		None
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

		match self.index_for_name(&name_squashed) {
			Some(_) => return Err(MensagoError::ErrExists),
			None => { /* do nothing */ }
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
			// db: rusqlite::Connection,
			domain: None,
			devid: None
		};

		if self.count_profiles() == 0 {
			profile.is_default = true;
			self.default_index = Some(1);
		}
		
		self.profiles.push(profile);

		Ok(self.profiles.get(self.profiles.len()-1).unwrap())
	}

	/// Deletes the named profile and all files on disk contained in it. On error, it returns a
	/// string description of the error or None on success.
	pub fn delete_profile(&mut self, name: &str) -> Option<String> {

		if name.len() == 0 {
			return Some(String::from("Empty data"))
		}

		let name_squashed = name.to_lowercase();
		if name_squashed == "default" {
			return Some(String::from("Profile name 'default' is reserved"))
		}

		let pindex = match self.index_for_name(&name_squashed) {
			None => return Some(String::from("Index not found")),
			Some(v) => v,
		};

		let profile = self.profiles.remove(pindex);
		if Path::new(profile.path.as_path()).exists() {
			match fs::remove_dir_all(profile.path.as_path()) {
				Err(e) => return Some(e.to_string()),
				Ok(_) => { /* continue on */ }
			}
		}

		if profile.is_default() && self.profiles.len() > 0 {
			self.profiles[0].set_default(true);
		}

		None
	}

	/// Returns the active profile
	pub fn get_active_profile(&self) -> Option<&Profile> {
		match self.active_index {
			Some(v) => self.profiles.get(v),
			None => None,
		}
	}

	/// Returns the default profile
	pub fn get_default_profile(&self) -> Option<&Profile> {
		match self.default_index {
			Some(v) => self.profiles.get(v),
			None => None,
		}
	}

	/// Returns a Vec of all available profiles
	pub fn get_profiles(&self) -> &Vec<Profile> {
		&self.profiles
	}

	/// Loads all profiles under the specified path. If None is passed to the function, the profile
	/// manager will look in ~/.config/mensago on POSIX platforms and %LOCALAPPDATA%\mensago on
	/// Windows. It returns None on success or a String error.
	pub fn load_profiles(&mut self, profile_path: Option<&PathBuf>) -> io::Result<()> {
		
		self.active_index = None;

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

			let profile = Profile::new(&itempath);
			self.profiles.push(profile);
			let mut profile = match self.profiles.get(self.profiles.len()-1) {
				None => panic!("BUG: Out of bounds in load_profiles()"),
				Some(v) => v
			};

			if profile.is_default() {
				match self.default_index {
					None => {
						profile.set_default(true);
						self.default_index = Some(self.profiles.len()-1);
					},
					Some(v) => {
						// If we have more than one profile marked as default, the one in the list
						// with the lower index retains that status
						profile.set_default(false);
					},
				}
			}
		}

		// If we've gotten through the entire loading process and we haven't got a single profile
		// loaded, then create one
		if self.profiles.len() == 0 {
			match self.create_profile("primary") {
				Ok(v) => {
					self.set_default_profile("primary");
				},
				Err(e) => {

					// TODO: Gotta figure out Rust's stupid complicated error-handling
					panic!("BUG: Unhandled error in load_profiles()");
				}
			}
		}
		
		match self.get_default_profile() {
			None => { /* We should never be here */ },
			Some(v) => {
				self.activate_profile(&v.name);
			}
		}
		
		Ok(())
	}

	pub fn rename_profile(&mut self, oldname: &str, newname: &str) -> Option<MensagoError> {

		// TODO: Implement rename_profile()

		Some(MensagoError::ErrUnimplemented)
	}

	pub fn set_default_profile(&mut self, name: &str) -> Option<&Profile> {

		// TODO: Implement set_default_profile()

		None
	}

	/// Obtains the index for a profile with the supplied name. Returns None on error.
	fn index_for_name(&self, name: &str) -> Option<usize> {
		
		if name.len() == 0 {
			return None
		}

		for i in 0..self.profiles.len() {
			let p = self.profiles.get(i)?;
			
			if p.name == name {
				return Some(i);
			}
		}

		None
	}	
}

