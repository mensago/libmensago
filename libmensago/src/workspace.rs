use crate::{auth, base::*, dbconn::*, dbfs::*, types::*};
use eznacl::*;
use libkeycard::*;
use std::fs;
use std::path::PathBuf;

/// The Workspace class is a model which represents a Mensago workspace
#[derive(Debug, PartialEq, Clone)]
pub struct Workspace {
    path: PathBuf,
    uid: Option<UserID>,
    wid: Option<RandomID>,
    domain: Option<Domain>,
    _type: String,
    pwhash: String,
}

impl Workspace {
    /// Creates a new, uninitialized Workspace object
    pub fn new(path: &PathBuf) -> Workspace {
        let mut storage = path.clone();
        storage.push("storage.db");

        return Workspace {
            path: path.clone(),
            uid: None,
            wid: None,
            domain: None,
            _type: String::from("identity"),
            pwhash: String::from(""),
        };
    }

    /// Returns the workspace ID of the workspace, assuming one has been set
    pub fn get_wid(&self) -> Option<RandomID> {
        self.wid.clone()
    }

    /// Returns the user ID of the workspace, assuming one has been set
    pub fn get_uid(&self) -> Option<UserID> {
        self.uid.clone()
    }

    /// Returns the domain of the workspace, assuming one has been set
    pub fn get_domain(&self) -> Option<Domain> {
        self.domain.clone()
    }

    /// Returns the workspace's address
    pub fn get_waddress(&self) -> Option<WAddress> {
        if self.domain.is_none() || self.wid.is_none() {
            return None;
        }

        Some(WAddress::from_parts(
            &self.wid.as_ref().unwrap(),
            &self.domain.as_ref().unwrap(),
        ))
    }

    /// Returns the workspace's Mensago address. Note that if the workspace does not have a UserID
    /// assigned, then this method will return a MAddress containing the workspace's regular
    /// address
    pub fn get_maddress(&self) -> Option<MAddress> {
        if self.domain.is_none() {
            return None;
        }

        if self.uid.is_none() {
            if self.wid.is_none() {
                return None;
            }
            return Some(MAddress::from_parts(
                &UserID::from_wid(self.wid.as_ref().unwrap()),
                &self.domain.as_ref().unwrap(),
            ));
        }
        Some(MAddress::from_parts(
            &self.uid.as_ref().unwrap(),
            &self.domain.as_ref().unwrap(),
        ))
    }

    /// Gets the human-friendly name for the workspace
    pub fn get_userid(&self) -> Result<UserID, MensagoError> {
        match self.uid.as_ref() {
            Some(v) => return Ok(v.clone()),
            None => return Err(MensagoError::ErrEmptyData),
        }
    }

    /// Sets the human-friendly name for the workspace
    pub fn set_userid(
        &mut self,
        conn: &mut DBConn,
        uid: Option<&UserID>,
    ) -> Result<(), MensagoError> {
        let uidstr = match uid {
            Some(v) => v.to_string(),
            None => String::new(),
        };

        conn.execute(
            "UPDATE workspaces SET userid=?1 WHERE wid=?2 AND domain=?3",
            &[
                uidstr.as_str(),
                self.wid.as_ref().unwrap().as_string(),
                self.domain.as_ref().unwrap().as_string(),
            ],
        )?;
        self.uid = match uid {
            Some(v) => Some(v.clone()),
            None => None,
        };

        Ok(())
    }

    /// Creates all the data needed for an individual workspace account
    pub fn generate(
        &mut self,
        conn: &mut DBConn,
        uid: Option<&UserID>,
        server: &Domain,
        wid: &RandomID,
        pwhash: &str,
    ) -> Result<(), MensagoError> {
        self.uid = match uid {
            Some(v) => Some(v.clone()),
            None => None,
        };
        self.wid = Some(wid.clone());
        self.domain = Some(server.clone());
        self.pwhash = String::from(pwhash);

        let waddr = WAddress::from_parts(&wid, &server);

        // Generate and add the workspace's various crypto keys

        let crepair = eznacl::EncryptionPair::generate("CURVE25519").unwrap();
        let _ = auth::add_keypair(
            conn,
            &waddr,
            &crepair.get_public_key(),
            &crepair.get_private_key(),
            "sha-256",
            &KeyType::AsymEncryptionKey,
            &KeyCategory::ConReqEncryption,
        )?;

        let crspair = eznacl::SigningPair::generate("ED25519").unwrap();
        let _ = auth::add_keypair(
            conn,
            &waddr,
            &crspair.get_public_key(),
            &crspair.get_private_key(),
            "sha-256",
            &KeyType::SigningKey,
            &KeyCategory::ConReqSigning,
        )?;

        let epair = eznacl::EncryptionPair::generate("CURVE25519").unwrap();
        let _ = auth::add_keypair(
            conn,
            &waddr,
            &epair.get_public_key(),
            &epair.get_private_key(),
            "sha-256",
            &KeyType::AsymEncryptionKey,
            &KeyCategory::Encryption,
        )?;

        let spair = eznacl::SigningPair::generate("ED25519").unwrap();
        let _ = auth::add_keypair(
            conn,
            &waddr,
            &spair.get_public_key(),
            &spair.get_private_key(),
            "sha-256",
            &KeyType::SigningKey,
            &KeyCategory::Signing,
        )?;

        let folderkey = eznacl::SecretKey::generate("XSALSA20").unwrap();
        let _ = auth::add_key(
            conn,
            &waddr,
            &folderkey.get_public_key(),
            "sha-256",
            &KeyCategory::Folder,
        )?;

        let storagekey = eznacl::SecretKey::generate("XSALSA20").unwrap();
        let _ = auth::add_key(
            conn,
            &waddr,
            &storagekey.get_public_key(),
            "sha-256",
            &KeyCategory::Storage,
        )?;

        let fkeyhash = get_hash("SHA-256", folderkey.get_public_str().as_bytes())?;

        for folder in [
            "/messages",
            "/contacts",
            "/events",
            "/tasks",
            "/notes",
            "/files",
            "/files/attachments",
        ] {
            self.add_folder(
                conn,
                &FolderMap {
                    fid: RandomID::generate(),
                    address: waddr.clone(),
                    keyid: fkeyhash.clone(),
                    path: DBPath::from(folder).unwrap(),
                    permissions: String::from("admin"),
                },
            )?;
        }

        // Create the folders for files and attachments
        let mut attachmentdir = self.path.clone();
        attachmentdir.push("files");
        attachmentdir.push("attachments");
        if !attachmentdir.exists() {
            match fs::create_dir_all(attachmentdir) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
            };
        }

        self.set_userid(conn, uid)?;

        Ok(())
    }

    /// Loads the workspace information from the local database. If no workspace ID is specified,
    /// the identity workspace for the profile is loaded.
    pub fn load_from_db(
        &mut self,
        conn: &mut DBConn,
        wid: Option<RandomID>,
    ) -> Result<(), MensagoError> {
        let widstr = match wid {
            Some(w) => String::from(w.to_string()),
            None => {
                let values =
                    conn.query("SELECT wid FROM workspaces WHERE type = 'identity'", [])?;
                if values.len() != 1 {
                    return Err(MensagoError::ErrNotFound);
                }
                if values[0].len() != 1 {
                    return Err(MensagoError::ErrSchemaFailure);
                }
                values[0][0].to_string()
            }
        };

        let values = conn.query(
            "SELECT domain,userid FROM workspaces WHERE wid = ?1",
            [widstr.to_string()],
        )?;
        if values.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if values[0].len() != 2 {
            return Err(MensagoError::ErrSchemaFailure);
        }
        let domstr = values[0][0].to_string();
        let uidstr = values[0][1].to_string();

        let tempdom = match Domain::from(&domstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(String::from(format!(
                    "Bad domain {} in load_from_db()",
                    domstr
                ))))
            }
        };
        let tempuid = match UserID::from(&uidstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(String::from(format!(
                    "Bad uid {} in load_from_db()",
                    uidstr
                ))))
            }
        };

        self.wid = match RandomID::from(&widstr.to_string()) {
            Some(v) => Some(v),
            None => {
                return Err(MensagoError::ErrProgramException(String::from(
                    "BUG: Invalid workspace ID in load_from_db",
                )))
            }
        };

        self.domain = Some(tempdom);
        self.uid = Some(tempuid);

        Ok(())
    }

    /// Adds the workspace instance to the storage database as the profile's identity workspace
    pub fn add_to_db(&self, conn: &mut DBConn, pw: &ArgonHash) -> Result<(), MensagoError> {
        match conn.exists("SELECT wid FROM workspaces WHERE type = 'identity'", []) {
            Ok(v) => {
                if v {
                    return Err(MensagoError::ErrExists);
                }
            }
            Err(_) => (),
        }

        let uidstr = match &self.uid {
            Some(v) => String::from(v.to_string()),
            None => String::new(),
        };

        if uidstr.len() > 0 {
            conn.execute(
                "INSERT INTO workspaces(wid,userid,domain,password,pwhashtype,type)
			VALUES(?1,?2,?3,?4,?5,?6)",
                &[
                    self.wid.as_ref().unwrap().as_string(),
                    &uidstr,
                    self.domain.as_ref().unwrap().as_string(),
                    pw.get_hash(),
                    pw.get_hashtype(),
                    &self._type,
                ],
            )?;
        } else {
            conn.execute(
                "INSERT INTO workspaces(wid,userid,domain,password,pwhashtype,type)
			VALUES(?1,?2,?3,?4,?5)",
                &[
                    self.wid.as_ref().unwrap().as_string(),
                    self.domain.as_ref().unwrap().as_string(),
                    pw.get_hash(),
                    pw.get_hashtype(),
                    &self._type,
                ],
            )?;
        }
        Ok(())
    }

    /// Removes ALL DATA associated with a workspace. Don't call this unless you mean to erase all
    /// evidence that a particular workspace ever existed.
    pub fn remove_from_db(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
        let address =
            WAddress::from_parts(self.wid.as_ref().unwrap(), &self.domain.as_ref().unwrap());

        // Clear out storage database
        match conn.exists(
            "SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2",
            [
                self.wid.as_ref().unwrap().to_string(),
                self.domain.as_ref().unwrap().to_string(),
            ],
        ) {
            Ok(v) => {
                if !v {
                    return Err(MensagoError::ErrNotFound);
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(String::from(
                    e.to_string(),
                )));
            }
        }

        conn.execute(
            "DELETE FROM workspaces WHERE wid=?1 AND domain=?2",
            &[
                self.wid.as_ref().unwrap().as_string(),
                self.domain.as_ref().unwrap().as_string(),
            ],
        )?;

        for table_name in ["folders", "messages", "notes", "keys", "sessions"] {
            conn.execute(
                &format!("DELETE FROM {} WHERE address=?1", table_name),
                [address.as_string()],
            )?;
        }

        Ok(())
    }

    /// Removes a workspace from the storage database. NOTE: This only removes the workspace entry
    /// itself. It does not remove keys, sessions, or other associated data.
    pub fn remove_workspace_entry(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
        match conn.exists(
            "SELECT wid FROM workspaces WHERE wid=?1 AND domain=?2",
            [
                self.wid.as_ref().unwrap().to_string(),
                self.domain.as_ref().unwrap().to_string(),
            ],
        ) {
            Ok(v) => {
                if !v {
                    return Err(MensagoError::ErrNotFound);
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(String::from(
                    e.to_string(),
                )));
            }
        }

        conn.execute(
            "DELETE FROM workspaces WHERE wid=?1 AND domain=?2",
            &[
                self.wid.as_ref().unwrap().as_string(),
                self.domain.as_ref().unwrap().as_string(),
            ],
        )
    }

    /// Adds a mapping of a folder ID to a specific path in the workspace
    pub fn add_folder(&self, conn: &mut DBConn, fmap: &FolderMap) -> Result<(), MensagoError> {
        match conn.exists(
            "SELECT fid FROM folders WHERE fid=?1",
            [fmap.fid.as_string()],
        ) {
            Ok(v) => {
                if v {
                    return Err(MensagoError::ErrExists);
                }
            }
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        conn.execute(
            "INSERT INTO folders(fid,address,keyid,path,name,permissions)
			VALUES(?1,?2,?3,?4,?5,?6)",
            [
                fmap.fid.to_string(),
                fmap.address.to_string(),
                fmap.keyid.to_string(),
                fmap.path.to_string(),
                String::from(fmap.path.basename()),
                fmap.permissions.clone(),
            ],
        )
    }

    /// Deletes a mapping of a folder ID to a specific path in the workspace
    pub fn remove_folder(&self, conn: &mut DBConn, fid: &RandomID) -> Result<(), MensagoError> {
        match conn.exists("SELECT fid FROM folders WHERE fid=?1", [fid.as_string()]) {
            Ok(v) => {
                if !v {
                    return Err(MensagoError::ErrNotFound);
                }
            }
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        match conn.execute("DELETE FROM folders WHERE fid=?1", [fid.as_string()]) {
            Ok(_) => return Ok(()),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    /// Gets the specified folder mapping.
    pub fn get_folder(&self, conn: &mut DBConn, fid: &RandomID) -> Result<FolderMap, MensagoError> {
        let values = conn.query(
            "SELECT address,keyid,path,permissions FROM folders WHERE fid=?1",
            [fid.to_string()],
        )?;
        if values.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if values[0].len() != 4 {
            return Err(MensagoError::ErrSchemaFailure);
        }

        let waddr = match WAddress::from(&values[0][0].to_string()) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(String::from(
                    "Bad address in get_folder()",
                )))
            }
        };
        let keyid = match CryptoString::from(&values[0][1].to_string()) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(String::from(
                    "Bad key ID in get_folder()",
                )))
            }
        };

        let fmap = FolderMap {
            fid: fid.clone(),
            address: waddr,
            keyid: keyid,
            path: DBPath::from(&values[0][2].to_string())?,
            permissions: values[0][3].to_string(),
        };

        Ok(fmap)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use eznacl::*;
    use libkeycard::*;
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

    fn setup_profile(testname: &str, path: &PathBuf) -> Result<ProfileManager, MensagoError> {
        let mut profman = ProfileManager::new(&path);
        let _ = match profman.create_profile("Primary") {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error creating profile 'Primary': {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        match profman.activate_profile("Primary") {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error activating profile 'Primary': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(profman)
    }

    #[test]
    fn workspace_generate_and_db() -> Result<(), MensagoError> {
        // Because so much is needed to just set up a workspace test, we'll do a few tests in this
        // function:
        // - generate()
        // - add_to_db()
        // - remove_from_db()
        // - remove_workspace_entry()

        let testname = String::from("workspace_generate_and_db");
        let test_path = setup_test(&testname);

        let mut profman = setup_profile(&testname, &test_path)?;
        let profile = profman.get_active_profile_mut().unwrap();

        // Hash of "CheeseCustomerSmugnessDelegatorGenericUnaudited"
        let pw = String::from(
            "$argon2id$v=19$m=1048576,t=1,p=2$jc/H+Cn1NwJBJOTmFqAdlA$\
			b2zoU9ZNhHlo/ZYuSJwoqUAXEdf1cbN3fxmbQhP0zJc",
        );

        let profpath = profile.path.clone();
        let mut w = Workspace::new(&profpath);
        let db = profile.get_db()?;
        match w.generate(
            db,
            Some(&UserID::from("testname").unwrap()),
            Domain::from("example.com").as_ref().unwrap(),
            RandomID::from("b5a9367e-680d-46c0-bb2c-73932a6d4007")
                .as_ref()
                .unwrap(),
            &pw,
        ) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error generating workspace: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #1: successful add
        let pwhash = ArgonHash::from_hashstr(&pw);
        match w.add_to_db(db, &pwhash) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding workspace to db: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #2: try to add when already in db
        match w.add_to_db(db, &pwhash) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch double adding workspace to db",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #3: successful remove from db
        match w.remove_from_db(db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error removing workspace from db: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #4: try to remove nonexistent
        match w.remove_from_db(db) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch removing nonexistent workspace from db",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #4: try to load nonexistent identity
        let mut testw = Workspace::new(&profpath);
        match testw.load_from_db(db, None) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch loading nonexistent identity from db",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #5: try to load other nonexistent workspace
        match testw.load_from_db(db, RandomID::from("00000000-0000-0000-0000-000000000000")) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch loading nonexistent identity from db",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Add again to test load_from_db and remove_workspace_entry()
        match w.add_to_db(db, &pwhash) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error re-adding workspace to db: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #6: successful load
        match testw.load_from_db(db, None) {
            Ok(_) => {
                // load_from_db doesn't get the password hash, so we'll just add it here to make
                // the comparison code simpler
                testw.pwhash = pwhash.to_string();
                if testw != w {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: data mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error loading workspace from db: {}",
                    testname,
                    e.to_string()
                )))
            }
        };

        // Case #7: successful remove_entry
        match w.remove_workspace_entry(db) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error removing workspace entry: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        Ok(())
    }

    #[test]
    fn workspace_folder() -> Result<(), MensagoError> {
        let testname = String::from("workspace_folder");
        let test_path = setup_test(&testname);

        let mut profman = setup_profile(&testname, &test_path)?;
        let profile = profman.get_profile_mut(0).unwrap();

        let folderkey =
            SecretKey::from_string("XSALSA20:TF_`Q2kZO;nUb(wWm1{P=_BmVe6rEK<GkITq@T|l").unwrap();
        let fkeyhash = get_hash("SHA-256", folderkey.get_public_str().as_bytes())?;

        let w = Workspace::new(&profile.path);
        let db = profile.get_db()?;

        // Case #1: Trying to get a non-existent folder mapping
        match w.get_folder(
            db,
            &RandomID::from("11111111-2222-3333-4444-555555666666").unwrap(),
        ) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch nonexistent folder mapping",
                    testname
                )))
            }
            Err(_) => (),
        }

        let foldermap = FolderMap {
            fid: RandomID::from("11111111-2222-3333-4444-555555666666").unwrap(),
            address: WAddress::from("aaaaaaaa-bbbb-cccc-dddd-eeeeeeffffff/example.com").unwrap(),
            keyid: fkeyhash.clone(),
            path: DBPath::from("/files/attachments").unwrap(),
            permissions: String::from("admin"),
        };

        // Case #2: Test add_folder
        match w.add_folder(db, &foldermap) {
            Ok(_) => (),
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error adding folder mapping '/files/attachments': {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // The amount of work put into making this code check all fields here with a loop is
        // stupidly *ridiculous*. Passing the tuple parameters using the recommended method,
        // parameter binding, doesn't work.
        //
        // The first iteration should be
        // "SELECT address FROM folders WHERE fid='11111111-2222-3333-4444-555555666666'". All
        // values passed to the query are confirmed as correct using the debugger. The query itself
        // was confirmed as correct by manually running the query using the SQLite client. YET
        // despite the correctnes of the query itself and the values returned, column name is
        // returned, not the correct value. ARRRRRRGH!!!
        //
        // Thankfully, we can hack around this and just use string subtitution and it just works.
        let fields = [
            (String::from("address"), foldermap.address.to_string()),
            (String::from("keyid"), fkeyhash.clone().to_string()),
            (String::from("path"), String::from("/files/attachments")),
            (String::from("name"), String::from("attachments")),
            (String::from("permissions"), String::from("admin")),
        ];

        for pair in fields {
            match db.get_db_value("folders", &pair.0, &foldermap.fid.to_string()) {
                Ok(v) => {
                    if v.to_string() != pair.1 {
                        return Err(MensagoError::ErrProgramException(format!(
                            "{}: wanted {} for {}, got {}",
                            testname,
                            &pair.1,
                            &pair.0,
                            v.to_string(),
                        )));
                    }
                }
                Err(e) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: error get folder mapping field {}: {}",
                        testname,
                        &pair.0,
                        e.to_string()
                    )))
                }
            }
        }

        // Case #3: trying to add a folder again
        match w.add_folder(db, &foldermap) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch duplicate folder mapping",
                    testname
                )))
            }
            Err(_) => (),
        }

        // Case #4: successful get_folder()
        match w.get_folder(db, &foldermap.fid) {
            Ok(v) => {
                if v.fid != foldermap.fid
                    || v.address != foldermap.address
                    || v.keyid != v.keyid
                    || v.path != foldermap.path
                    || v.permissions != foldermap.permissions
                {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: data mismatch",
                        testname
                    )));
                }
            }
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error getting folder mapping: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #5: successful remove_folder()
        match w.remove_folder(db, &foldermap.fid) {
            Ok(_) => match w.get_folder(db, &foldermap.fid) {
                Ok(_) => {
                    return Err(MensagoError::ErrProgramException(format!(
                        "{}: remove_folder failed to remove db entry",
                        testname
                    )))
                }
                Err(_) => (),
            },
            Err(e) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: error removing folder mapping: {}",
                    testname,
                    e.to_string()
                )))
            }
        }

        // Case #6: try to remove nonexistent folder
        match w.remove_folder(db, &foldermap.fid) {
            Ok(_) => {
                return Err(MensagoError::ErrProgramException(format!(
                    "{}: failed to catch removing nonexistent folder mapping",
                    testname
                )))
            }
            Err(_) => (),
        }

        Ok(())
    }
}
