use crate::base::*;
use crate::config::*;
use crate::workspace::*;
use libkeycard::*;
use rusqlite;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// String for initializing a new profile database
static STORAGE_DB_SETUP_COMMANDS: &str = "
	BEGIN;
	CREATE TABLE 'workspaces' (
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
	CREATE table 'keycards'(
		'rowid' INTEGER PRIMARY KEY AUTOINCREMENT,
		'owner' TEXT NOT NULL,
		'entryindex' TEXT NOT NULL,
		'type' TEXT NOT NULL,
		'entry' BLOB NOT NULL,
		'textentry' TEXT NOT NULL,
		'hash' TEXT NOT NULL,
		'expires' TEXT NOT NULL,
		'timestamp' TEXT NOT NULL,
		'ttlexpires' TEXT
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
	CREATE TABLE 'contacts' (
		'conid' TEXT NOT NULL UNIQUE,
		'entitytype' TEXT NOT NULL,
        'group' TEXT NOT NULL,
        'gender' TEXT,
        'bio' TEXT,
        'anniversary' TEXT,
        'birthday' TEXT,
        'organization' TEXT,
        'title' TEXT,
        'notes' TEXT,
        'annotation' BOOL,
        'annotation_link' TEXT
	);
    CREATE TABLE 'contact_names' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'formatted_name' TEXT NOT NULL,
        'given_name' TEXT NOT NULL,
        'family_name' TEXT,
        'prefix' TEXT
    );
    CREATE TABLE 'contact_nameparts' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'parttype' TEXT NOT NULL,
        'value' TEXT NOT NULL,
        'priority' TEXT NOT NULL
    );
    CREATE TABLE 'contact_mensago' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'label' TEXT NOT NULL,
        'uid' TEXT NOT NULL,
        'wid' TEXT NOT NULL,
        'domain' TEXT NOT NULL
    );
    CREATE TABLE 'contact_address' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'label' TEXT NOT NULL,
        'street' TEXT,
        'extended' TEXT,
        'locality' TEXT,
        'region' TEXT,
        'postalcode' TEXT,
        'country' TEXT,
        'preferred' BOOL
    );
    CREATE TABLE 'contact_keyvalue' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'itemtype' TEXT NOT NULL,
        'label' TEXT NOT NULL,
        'value' TEXT
    );
    CREATE TABLE 'contact_photo' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL UNIQUE,
        'mime' TEXT NOT NULL,
        'data' BLOB
    );
    CREATE TABLE 'contact_files' (
        'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'name' TEXT NOT NULL UNIQUE,
        'mime' TEXT NOT NULL,
        'data' BLOB
    );
	CREATE TABLE 'updates' (
		'id' TEXT NOT NULL UNIQUE,
		'type' TEXT NOT NULL,
		'data' TEXT NOT NULL,
		'time' TEXT NOT NULL
	);
	CREATE TABLE 'photos' (
		'id' TEXT NOT NULL UNIQUE,
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
	);
	COMMIT;";

static SECRETS_DB_SETUP_COMMANDS: &str = "
	BEGIN;
	CREATE table 'keys' (
		'keyid' TEXT NOT NULL UNIQUE,
		'address' TEXT NOT NULL,
		'type' TEXT NOT NULL,
		'category' TEXT NOT NULL,
		'private' TEXT NOT NULL,
		'public' TEXT,
		'timestamp' TEXT NOT NULL
	);
	CREATE table 'sessions'(
		'address' TEXT NOT NULL,
		'devid' TEXT NOT NULL,
		'devname' TEXT NOT NULL,
		'public_key' TEXT NOT NULL,
		'private_key' TEXT NOT NULL,
		'os' TEXT NOT NULL
	);
    CREATE TABLE 'contact_keys' (
		'id' TEXT NOT NULL UNIQUE,
        'conid' TEXT NOT NULL,
        'label' TEXT NOT NULL UNIQUE,
        'category' TEXT NOT NULL,
        'value' TEXT NOT NULL,
		'timestamp' TEXT NOT NULL
    );
    COMMIT;
";

/// The Profile type is the client's entry point to interacting with local storage. A profile
/// consists of a SQLCipher database for storing user data (messages, etc) and config info
/// and a SQLCipher database for storing secrets (signing keys, password hash, etc.). Neither
/// database is encrypted currently, but will be a future date. Each profile also contains a
/// folder called 'files' for storing files outside the databases to cut down on bloat and make
/// it easier for the user to access attachments with other programs in the OS.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub path: PathBuf,
    pub is_default: bool,
    pub uid: Option<UserID>,
    pub wid: Option<RandomID>,
    pub domain: Option<Domain>,
    pub devid: Option<RandomID>,
    pub config: Config,
}

impl Profile {
    /// Creates a new profile from a specified path
    fn new(profpath: &Path) -> Result<Profile, MensagoError> {
        let profname = match profpath.to_str() {
            Some(_) => String::from(profpath.file_name().unwrap().to_str().unwrap()),
            None => return Err(MensagoError::ErrUTF8),
        };
        if profname.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        let mut profile = Profile {
            name: String::from(profname),
            path: PathBuf::from(profpath),
            is_default: false,
            uid: None,
            wid: None,
            domain: None,
            devid: None,
            config: Config::new(""),
        };

        let mut defpath = profile.path.to_path_buf();
        defpath.push("default.txt");
        if defpath.exists() {
            profile.is_default = true;
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

        let mut storagepath = self.path.clone();
        storagepath.push("storage.db");
        if storagepath.exists() {
            let db = rusqlite::Connection::open(storagepath)?;
            self.config.load_from_db(&db)?;
            db.close()
                .expect("BUG: Profile.activate(): error closing database");
            return Ok(());
        }

        self.reset_db()
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

    /// Returns the profiles identity workspace address
    pub fn get_waddress(&self) -> Option<WAddress> {
        if self.domain.is_none() || self.wid.is_none() {
            return None;
        }

        Some(WAddress::from_parts(
            &self.wid.as_ref().unwrap(),
            &self.domain.as_ref().unwrap(),
        ))
    }

    /// Returns the identity workspace address for the profile
    pub fn get_identity(&mut self) -> Result<MAddress, MensagoError> {
        if self.uid.is_some() && self.domain.is_some() {
            return Ok(MAddress::from_parts(
                self.uid.as_ref().unwrap(),
                self.domain.as_ref().unwrap(),
            ));
        }

        if self.wid.is_some() && self.domain.is_some() {
            return Ok(MAddress::from_parts(
                &UserID::from_wid(self.wid.as_ref().unwrap()),
                self.domain.as_ref().unwrap(),
            ));
        }

        // We got this far, which means we need to get the info from the profile database
        {
            let conn = self.open_storage()?;

            let mut stmt = match conn
                .prepare("SELECT wid,domain,userid FROM workspaces WHERE type = 'identity'")
            {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            // Queries with rusqlite are extremely ugly because the results wrapped several layers
            // deep. The query() call returns a Result containing a Rows() structure. If we get an
            // error here, there was a problem either with the query or the database.
            let mut rows = match stmt.query([]) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            // The Rows::next() call returns Result<Some<Result<Row>>>. Seriously. The possible
            // return values are:
            //
            // Err() -> an error occurred getting the next row
            // Ok(Some(Row)) -> another row was returned
            // Ok(None) -> all results have been returned

            let option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            // We've actually removed enough layers to get an idea of if we actually were successful
            // in finding the identity info.
            if option_row.is_none() {
                // We have a problem: no identity entry in the database for the workspace.
                return Err(MensagoError::ErrDatabaseException(String::from(
                    "Database has no identity entry in 'workspaces'",
                )));
            }

            let row = option_row.unwrap();
            if self.wid.is_none() {
                self.wid = RandomID::from(&row.get::<usize, String>(0).unwrap());
            }
            if self.domain.is_none() {
                self.domain = Domain::from(&row.get::<usize, String>(1).unwrap());
            }
            if self.uid.is_none() {
                self.uid = UserID::from(&row.get::<usize, String>(2).unwrap());
            }

            // Connection to the database will be closed when the connection object is dropped
        }

        if self.uid.is_some() && self.domain.is_some() {
            return Ok(MAddress::from_parts(
                self.uid.as_ref().unwrap(),
                self.domain.as_ref().unwrap(),
            ));
        }

        if self.wid.is_some() && self.domain.is_some() {
            return Ok(MAddress::from_parts(
                &UserID::from_wid(self.wid.as_ref().unwrap()),
                self.domain.as_ref().unwrap(),
            ));
        }

        return Err(MensagoError::ErrProgramException(String::from(
            "BUG: Malformed MAddress returned from get_identity",
        )));
    }

    /// Assigns an identity workspace to the profile. The profile can have multiple workspace
    /// memberships, but only one can be used for the identity of the user. This call sets that
    /// address. Because so much is tied to an identity workspace, once this is set, it cannot be
    /// changed.
    pub fn set_identity(&mut self, w: Workspace, pw: &ArgonHash) -> Result<(), MensagoError> {
        // First, check to see if we already have one in the database. If so, return an error
        // because once set, it cannot be changed.

        if self.domain.is_some() && (self.uid.is_some() || self.wid.is_some()) {
            return Err(MensagoError::ErrExists);
        }

        let conn = self.open_storage()?;

        // Cached version doesn't exist, so check the database
        {
            let mut stmt = match conn
                .prepare("SELECT wid,domain,userid FROM workspaces WHERE type = 'identity'")
            {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut rows = match stmt.query([]) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            if option_row.is_some() {
                // Identity exists, return an error
                return Err(MensagoError::ErrExists);
            }
        }

        w.add_to_db(pw)?;

        self.wid = w.get_wid();
        self.uid = w.get_uid();
        self.domain = w.get_domain();

        Ok(())
    }

    /// Reinitializes the profile's database to empty
    pub fn reset_db(&self) -> Result<(), MensagoError> {
        let strdata = [
            ("storage.db", STORAGE_DB_SETUP_COMMANDS),
            ("secrets.db", SECRETS_DB_SETUP_COMMANDS),
        ];

        for s in strdata {
            let mut dbpath = self.path.clone();
            dbpath.push(s.0);

            if dbpath.exists() {
                fs::remove_file(&dbpath)?;
            }

            {
                let conn = match rusqlite::Connection::open(&dbpath) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(MensagoError::ErrDatabaseException(String::from(
                            e.to_string(),
                        )));
                    }
                };

                match conn.execute_batch(s.1) {
                    Ok(_) => (),
                    Err(e) => {
                        return Err(MensagoError::ErrDatabaseException(String::from(
                            e.to_string(),
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Resolves a Mensago address to its corresponding workspace ID
    pub fn resolve_address(&self, a: MAddress) -> Result<RandomID, MensagoError> {
        let conn = self.open_storage()?;

        let mut stmt =
            match conn.prepare("SELECT wid FROM workspaces WHERE userid=?1 AND domain=?2") {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

        let mut rows = match stmt.query([a.get_uid().as_string(), a.get_domain().as_string()]) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        if option_row.is_none() {
            // We have a problem: no identity entry in the database for the workspace.
            return Err(MensagoError::ErrDatabaseException(String::from(
                "Database has no identity",
            )));
        }

        let row = option_row.unwrap();
        match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
            Some(v) => Ok(v),
            None => Err(MensagoError::ErrDatabaseException(String::from(
                "Bad identity workspace ID in database",
            ))),
        }
    }

    /// Creates a connection to the profile's database for storage of keys
    pub fn open_secrets(&self) -> Result<rusqlite::Connection, rusqlite::Error> {
        let mut dbpath = self.path.clone();
        dbpath.push("secrets.db");
        rusqlite::Connection::open_with_flags(dbpath, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
    }

    /// Creates a connection to the profile's main storage database
    pub fn open_storage(&self) -> Result<rusqlite::Connection, rusqlite::Error> {
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
            _ => return Err(MensagoError::ErrNotFound),
        };

        self.profile_id = name_squashed;
        self.active_index = active_index;
        self.profiles[active_index as usize].activate()?;

        // Force loading of basic identity info if it hasn't already been done
        match self.profiles[active_index as usize].get_identity() {
            Ok(_) => (),
            Err(_) => {
                // We ignore errors because uninitialized profiles won't have any identity info
            }
        }

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
    pub fn create_profile(&mut self, name: &str) -> Result<&mut Profile, MensagoError> {
        if name.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        let name_squashed = name.to_lowercase();
        if name_squashed == "default" {
            return Err(MensagoError::ErrReserved);
        }

        if self.index_for_name(&name_squashed) >= 0 {
            return Err(MensagoError::ErrExists);
        }

        let mut new_profile_path = PathBuf::from(&self.profile_folder);
        new_profile_path.push(&name_squashed);
        match fs::DirBuilder::new()
            .recursive(true)
            .create(new_profile_path.as_path())
        {
            Err(_) => return Err(MensagoError::ErrFilesytemError),
            Ok(_) => (),
        }

        let mut profile = Profile {
            name: name_squashed.clone(),
            path: new_profile_path,
            is_default: false,
            uid: None,
            wid: None,
            domain: None,
            devid: Some(RandomID::generate()),
            config: Config::new(""),
        };

        if self.count_profiles() == 0 {
            profile.is_default = true;
            self.default_index = 1;

            let mut defaultpath = PathBuf::from(&self.profile_folder);
            defaultpath.push(&name_squashed);
            defaultpath.push("default.txt");
            if !defaultpath.exists() {
                let _ = fs::File::create(defaultpath)?;
            }
        }

        profile.reset_db()?;
        self.profiles.push(profile);

        let length = self.profiles.len() - 1;
        Ok(self.profiles.get_mut(length).unwrap())
    }

    /// Deletes the named profile and all files on disk contained in it.
    pub fn delete_profile(&mut self, name: &str) -> Result<(), MensagoError> {
        if name.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        let name_squashed = name.to_lowercase();
        if name_squashed == "default" {
            return Err(MensagoError::ErrReserved);
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
                Ok(_) => (),
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Returns the active profile
    pub fn get_active_profile(&self) -> Option<&Profile> {
        match self.active_index {
            v if v >= 0 => self.profiles.get(self.active_index as usize),
            _ => None,
        }
    }

    /// Returns the active profile
    pub fn get_active_profile_mut(&mut self) -> Option<&mut Profile> {
        match self.active_index {
            v if v >= 0 => self.profiles.get_mut(self.active_index as usize),
            _ => None,
        }
    }

    /// Returns the default profile
    pub fn get_default_profile(&self) -> Option<&Profile> {
        match self.default_index {
            v if v >= 0 => self.profiles.get(self.default_index as usize),
            _ => None,
        }
    }

    /// Returns the specified profile
    pub fn get_profile(&self, index: usize) -> Option<&Profile> {
        self.profiles.get(index)
    }

    /// Returns the specified profile as mutable
    pub fn get_profile_mut(&mut self, index: usize) -> Option<&mut Profile> {
        self.profiles.get_mut(index)
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
            }
        };

        if !self.profile_folder.exists() {
            fs::create_dir_all(self.profile_folder.as_path())?;
        }

        self.profiles.clear();
        for item in fs::read_dir(self.profile_folder.as_path())? {
            let entry = item?;
            let itempath = entry.path();
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
                    self.default_index = (self.profiles.len() - 1) as isize;
                }
            }
        }

        // If we've gotten through the entire loading process and we haven't got a single profile
        // loaded, then create one
        if self.profiles.len() == 0 {
            match self.create_profile("primary") {
                Ok(_) => {
                    self.set_default_profile("primary")?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        let default_name = match self.get_default_profile() {
            Some(v) => String::from(&v.name),
            None => {
                return Err(MensagoError::ErrProgramException(String::from(
                    "BUG: Couldn't find default profile in load_profiles()",
                )));
            }
        };

        self.activate_profile(&default_name)?;

        Ok(())
    }

    /// Renames the profile from the old name to the new one
    pub fn rename_profile(&mut self, oldname: &str, newname: &str) -> Result<(), MensagoError> {
        if oldname.len() == 0 || newname.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        let old_squashed = oldname.to_lowercase();
        let new_squashed = newname.to_lowercase();

        let index = match self.index_for_name(&old_squashed) {
            v if v >= 0 => v,
            _ => return Err(MensagoError::ErrNotFound),
        };

        if self.index_for_name(&new_squashed) >= 0 {
            return Err(MensagoError::ErrExists);
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
            return Err(MensagoError::ErrEmptyData);
        }

        if self.profiles.len() == 1 {
            if !self.profiles[0].is_default() {
                self.profiles[0].set_default(true)?;
            }
            self.default_index = 0;
            return Ok(());
        }

        let mut oldindex: isize = -1;
        for i in 0..self.profiles.len() {
            if self.profiles[i].is_default() {
                oldindex = i as isize;
                break;
            }
        }

        let name_squashed = name.to_lowercase();
        let newindex = match self.index_for_name(&name_squashed) {
            x if x >= 0 => x,
            _ => return Err(MensagoError::ErrNotFound),
        };

        if oldindex <= 0 {
            if name_squashed == self.profiles[oldindex as usize].name {
                return Ok(());
            }
            self.profiles[oldindex as usize].set_default(false)?;
        }

        self.profiles[newindex as usize].set_default(true)
    }

    /// Obtains the index for a profile with the supplied name. Returns None on error.
    fn index_for_name(&self, name: &str) -> isize {
        if name.len() == 0 {
            return -1;
        }

        for i in 0..self.profiles.len() {
            let p = match self.profiles.get(i) {
                Some(v) => v,
                None => {
                    return -1;
                }
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
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;

    // Sets up the path to contain the profile tests
    fn setup_test(name: &str) -> PathBuf {
        if name.len() < 1 {
            panic!("Invalid name {} in setup_test", name);
        }
        let args: Vec<String> = env::args().collect();
        let test_path = PathBuf::from_str(&args[0]).unwrap();
        let mut test_path = test_path.parent().unwrap().to_path_buf();
        test_path.push("testfiles");
        test_path.push(name);

        if test_path.exists() {
            fs::remove_dir_all(&test_path).unwrap();
        }
        fs::create_dir_all(&test_path).unwrap();

        test_path
    }

    #[test]
    fn test_profile_dbinit() -> Result<(), String> {
        let testname = String::from("profile_dbinit");
        let test_path = setup_test(&testname);
        let p = match Profile::new(test_path.as_path()) {
            Ok(v) => v,
            Err(e) => return Err(format!("{}: {}", testname, e.to_string())),
        };
        match p.reset_db() {
            Ok(_) => (),
            Err(e) => return Err(format!("{}: {}", testname, e.to_string())),
        }

        Ok(())
    }

    #[test]
    fn test_profman_init() -> Result<(), String> {
        // Because so much is done in the constructor, this unit performs basic tests on the
        // following:
        //
        // load_profiles()
        // _index_for_profile()
        // create_profile()
        // get_default_profile()
        // set_default_profile()
        // activate_profile()
        // reset_db()

        let testname = String::from("profman_init");
        let test_path = setup_test(&testname);
        let mut pm = ProfileManager::new(&test_path);
        match pm.load_profiles(Some(&test_path)) {
            Ok(_) => (),
            Err(e) => return Err(format!("{}: {}", testname, e.to_string())),
        }

        Ok(())
    }

    #[test]
    fn test_profman_create_delete() -> Result<(), String> {
        let testname = String::from("profman_create_delete");
        let test_path = setup_test(&testname);
        let mut pm = ProfileManager::new(&test_path);
        match pm.load_profiles(Some(&test_path)) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to load profiles: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.create_profile("") {
            Ok(_) => {
                return Err(format!(
                    "{}: create failed to handle empty string",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.create_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to create profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.delete_profile("") {
            Ok(_) => {
                return Err(format!(
                    "{}: delete failed to handle empty string",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.delete_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to delete profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.delete_profile("secondary") {
            Ok(_) => {
                return Err(format!(
                    "{}: delete failed to handle nonexistent profile",
                    testname
                ))
            }
            Err(_) => (),
        }

        Ok(())
    }

    #[test]
    fn test_profman_rename() -> Result<(), String> {
        // Rename tests: empty old name (fail), empty new name (fail), old name == new name,
        // missing old name profile, existing new name profile, successful rename

        let testname = String::from("profman_rename");
        let test_path = setup_test(&testname);
        let mut pm = ProfileManager::new(&test_path);
        match pm.load_profiles(Some(&test_path)) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to load profiles: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.rename_profile("", "foo") {
            Ok(_) => {
                return Err(format!(
                    "{}: rename failed to handle empty old name",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.rename_profile("foo", "") {
            Ok(_) => {
                return Err(format!(
                    "{}: rename failed to handle empty new name",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.rename_profile("secondary", "secondary") {
            Ok(_) => {
                return Err(format!(
                    "{}: rename failed to handle rename to self",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.create_profile("foo") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to create test profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.rename_profile("primary", "foo") {
            Ok(_) => {
                return Err(format!(
                    "{}: rename failed to handle existing new profile name",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.rename_profile("foo", "secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to rename profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        Ok(())
    }

    #[test]
    fn test_profman_activate() -> Result<(), String> {
        let testname = String::from("profman_activate");
        let test_path = setup_test(&testname);
        let mut pm = ProfileManager::new(&test_path);
        match pm.load_profiles(Some(&test_path)) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to load profiles: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.create_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to create test profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.activate_profile("") {
            Ok(_) => return Err(format!("{}: failed to handle empty string", testname)),
            Err(_) => (),
        }

        match pm.activate_profile("foo") {
            Ok(_) => {
                return Err(format!(
                    "{}: failed to handle nonexistent profile",
                    testname
                ))
            }
            Err(_) => (),
        }

        match pm.activate_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to activate test profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        Ok(())
    }

    #[test]
    fn test_profman_multitest() -> Result<(), String> {
        let testname = String::from("profman_multitest");
        let test_path = setup_test(&testname);
        let mut pm = ProfileManager::new(&test_path);
        match pm.load_profiles(Some(&test_path)) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to load profiles: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.create_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to create test profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.activate_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to activate secondary profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.set_default_profile("secondary") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to secondary profile as default: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.rename_profile("primary", "trash") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to rename primary profile to trash: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        match pm.delete_profile("trash") {
            Ok(_) => (),
            Err(e) => {
                return Err(format!(
                    "{} failed to delete trash profile: {}",
                    testname,
                    e.to_string()
                ))
            }
        }

        Ok(())
    }
}
