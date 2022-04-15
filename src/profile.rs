use std::fs::{remove_dir_all, DirBuilder};
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
	profile_folder: String,
	active_index: usize,
	default_index: usize
}

impl ProfileManager {

	pub fn activate_profile(name: &str) -> Option<&'static Profile> {

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
		match DirBuilder::new().recursive(true).create(new_profile_path.as_path()) {
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
			match remove_dir_all(profile.path.as_path()) {
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
		self.profiles.get(self.active_index)
	}

	/// Returns the default profile
	pub fn get_default_profile(&self) -> Option<&Profile> {
		self.profiles.get(self.default_index)
	}

	/// Returns a Vec of all available profiles
	pub fn get_profiles(&self) -> &Vec<Profile> {
		&self.profiles
	}

	pub fn load_profiles(profile_path: Option<&str>) {

		// TODO: Implement load_profiles()

	}

	pub fn rename_profile(oldname: &str, newname: &str) -> Option<MensagoError> {

		// TODO: Implement rename_profile()

		Some(MensagoError::ErrUnimplemented)
	}

	pub fn set_default_profile(name: &str) -> Option<&Profile> {

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

