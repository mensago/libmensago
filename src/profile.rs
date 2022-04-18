use anyhow::Result;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use crate::base::*;
use crate::types::*;
use crate::workspace::*;


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
	pub fn new(profpath: &Path) -> Result<Profile, MensagoError> {

		// TODO: Finish immplementing Profile::new()

		Ok(Profile{
			name: String::from(""),
			path: PathBuf::from(profpath),
			is_default: false,
			uid: None,
			wid: None,
			domain: None,
			devid: None,
		})
	}

	/// Connects the profile to its associated database
	pub fn activate(&mut self) -> Result<(), MensagoError> {

		// TODO: Implement Profile::activate()

		return Err(MensagoError::ErrUnimplemented)
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

	/// Disconnects the profile to its associated database
	pub fn deactivate(&mut self) {

		// TODO: Implement Profile::deactivate()
	}

	/// Sets the profile's internal flag that it is the default profile
	pub fn set_default(&mut self, is_default: bool) -> Result<(), MensagoError> {

		// TODO: Implement Profile::set_default()
	
		self.is_default = is_default;

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Returns true if the profile has been told it's the default
	pub fn is_default(&self) -> bool {
		return self.is_default;
	}

	/// Returns the identity workspace address for the profile
	pub fn get_identity(&self) -> Result<MAddress,MensagoError> {

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Assigns an identity workspace to the profile
	pub fn set_identity(&self, w: Workspace) -> Result<(),MensagoError> {

		return Err(MensagoError::ErrUnimplemented)
	}

	/// Reinitializes the profile's database to empty
	pub fn reset_db(&self) -> Result<(),MensagoError> {

		return Err(MensagoError::ErrUnimplemented)
	}
	
	/// Resolves a Mensago address to its corresponding workspace ID
	pub fn resolve_address(&self, a: MAddress) -> Result<RandomID,MensagoError> {

		return Err(MensagoError::ErrUnimplemented)
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
}

impl ProfileManager {

	pub fn activate_profile(&mut self, name: &str) -> Result<&Profile, MensagoError> {

		// TODO: Implement activate_profile()

		return Err(MensagoError::ErrUnimplemented);
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
			None => return Err(MensagoError::ErrNotFound),
			Some(v) => v,
		};

		let profile = self.profiles.remove(pindex);
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
					self.set_default_profile("primary");
				},
				Err(e) => {
					return Err(e);
				}
			}
		}
		
		let default_name = match self.get_default_profile() {
			Some(v) => String::from(&v.name),
			None => panic!("BUG: Couldn't find default profile in load_profiles()"),
		};

		self.activate_profile(&default_name)?;
		
		Ok(())
	}

	pub fn rename_profile(&mut self, oldname: &str, newname: &str) -> Result<(), MensagoError> {

		if oldname.len() == 0 || newname.len() == 0 {
			return Err(MensagoError::ErrEmptyData)
		}

		let old_squashed = oldname.to_lowercase();
		let new_squashed = newname.to_lowercase();

		let index = match self.index_for_name(&old_squashed) {
			Some(v) => v,
			None => return Err(MensagoError::ErrNotFound)
		};

		if self.index_for_name(&new_squashed) != None {
			return Err(MensagoError::ErrExists)
		}

		if index == self.active_index as usize {
			// TODO: deactivate profile
		}

		// TODO: Finish implementing rename_profile()

		Err(MensagoError::ErrUnimplemented)
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

