use crate::*;
use eznacl::*;
use home::home_dir;
use hostname;
use libkeycard::*;
use std::env;
use std::path::PathBuf;

/// The Client type primary interface to the entire library.
pub struct Client {
    conn: ServerConnection,
    pman: ProfileManager,
    is_admin: bool,
    login_active: bool,
    dns: Box<dyn DNSHandlerT>,
    expiration: u16,
    use_certified: bool,
}

impl Client {
    /// Instantiates a new Mensago client instance. The profile folder passed to the method is the
    /// location of the top-level folder that contains all profiles.
    pub fn new(
        profile_folder: &str,
        dns: Box<dyn DNSHandlerT>,
        use_certified: bool,
    ) -> Result<Client, MensagoError> {
        let mut pman = ProfileManager::new(&PathBuf::from(&profile_folder));
        pman.load_profiles(Some(&PathBuf::from(&profile_folder)))?;

        Ok(Client {
            conn: ServerConnection::new(),
            pman,
            is_admin: false,
            login_active: false,
            dns,
            expiration: 90,
            use_certified,
        })
    }

    /// Establishes a network connection to a Mensago server. Logging in is not performed.
    pub fn connect(&mut self, domain: &Domain) -> Result<(), MensagoError> {
        _ = self.disconnect();

        let serverconfig = get_server_config(domain, &mut *self.dns)?;
        if serverconfig.len() == 0 {
            return Err(MensagoError::ErrNotFound);
        }
        let ip = self.dns.lookup_a(&serverconfig[0].server)?;
        self.conn.connect(&ip.to_string(), serverconfig[0].port)
    }

    /// Returns true if the client is connected to a Mensago server.
    #[inline]
    pub fn is_connected(&self) -> bool {
        self.conn.is_connected()
    }

    /// Returns a reference to the client's ServerConnection instance
    #[inline]
    pub fn get_connection(&self) -> &ServerConnection {
        &self.conn
    }

    /// Returns a mutable reference to the client's ServerConnection instance
    #[inline]
    pub fn get_connection_mut(&mut self) -> &mut ServerConnection {
        &mut self.conn
    }

    /// Gracefully closes a connection with a Mensago server.
    pub fn disconnect(&mut self) -> Result<(), MensagoError> {
        if self.is_connected() {
            self.conn.disconnect()
        } else {
            Ok(())
        }
    }

    /// Returns the number of days after which new keycard entries will expire. The default is the
    /// recommended value of 90.
    #[inline]
    pub fn get_expiration(&self) -> u16 {
        self.expiration
    }

    /// Logs into a server. Note that while logging in and connecting are not the same, if this
    /// call is made while not connected to a server, an attempt to connect will be made.
    pub fn login(&mut self, address: &MAddress) -> Result<(), MensagoError> {
        if !self.is_connected() {
            self.connect(address.get_domain())?;
        }

        let record = get_mgmt_record(address.get_domain(), self.dns.as_mut())?;
        let profile = match self.pman.get_active_profile_mut() {
            Some(v) => v,
            None => return Err(MensagoError::ErrNoProfile),
        };

        let waddr = match address.get_uid().get_type() {
            IDType::WorkspaceID => WAddress::from_maddress(&address).unwrap(),
            IDType::UserID => {
                let mut resolver = KCResolver::new(&profile)?;
                let wid = resolver.resolve_address(&address, self.dns.as_mut())?;
                WAddress::from_parts(&wid, address.get_domain())
            }
        };

        let serverkey = EncryptionKey::from(&record.ek)?;
        login(&mut self.conn, waddr.get_wid(), &serverkey)?;

        let db = profile.get_db()?;
        let passhash = get_credentials(db, &waddr)?;

        password(&mut self.conn, &passhash)?;

        let devpair = get_session_keypair(db, &waddr)?;
        self.is_admin = device(&mut self.conn, waddr.get_wid(), &devpair)?;

        self.login_active = true;
        Ok(())
    }

    /// Returns true if the client is connected to an active login session
    pub fn is_logged_in(&mut self) -> bool {
        if self.is_connected() {
            return self.login_active;
        }
        self.login_active = false;
        return false;
    }

    /// Returns true if the client is connected to an active login session and the user has
    /// administrator rights in the session.
    pub fn is_admin(&mut self) -> bool {
        return self.is_logged_in() && self.is_admin;
    }

    /// Logs out of any active login sessions. This does not disconnect from the server itself;
    /// instead it reverts the session to an unauthenticated state.
    pub fn logout(&mut self) -> Result<(), MensagoError> {
        self.login_active = false;
        self.is_admin = false;
        if self.is_connected() {
            logout(&mut self.conn)
        } else {
            Ok(())
        }
    }

    /// Returns a reference to the client's profile manager
    pub fn get_profile_manager(&mut self) -> &mut ProfileManager {
        &mut self.pman
    }

    /// Administrator command which preprovisions a new account on the server.
    ///
    /// This is a simple command because it is not meant to create a local profile. It is only meant
    /// to provision the account on the server side. The administrator receives the information in
    /// the PreRegInfo structure and gives it to the user to finish account setup.
    pub fn preregister(
        &mut self,
        uid: Option<&UserID>,
        domain: Option<&Domain>,
    ) -> Result<PreregInfo, MensagoError> {
        if !self.is_logged_in() {
            return Err(MensagoError::ErrNoLogin);
        }
        if !self.is_admin() {
            return Err(MensagoError::ErrNotAdmin);
        }

        if uid.is_none() {
            return preregister(&mut self.conn, None, None, domain);
        }

        match uid.unwrap().get_type() {
            IDType::WorkspaceID => {
                let wid = RandomID::from_userid(uid.as_ref().unwrap()).unwrap();
                preregister(&mut self.conn, Some(&wid), None, domain)
            }
            IDType::UserID => preregister(&mut self.conn, None, uid, domain),
        }
    }

    /// Completes setup of a preregistered account. The call requires information that the account
    /// administrator would have given to the user: the account address, the registration code from
    /// `preregister()`, and the user's cleartext password.
    ///
    /// This command initializes the user's local profile and does almost everything needed for the
    /// user to get to work. It does _not_ set the user's personal information, such as their name.
    /// If the user wants their name in their keycard, this will need to be set before calling
    /// `update_keycard()`, which is the final step in setting up a user profile.
    pub fn redeem_regcode(
        &mut self,
        address: &MAddress,
        user_regcode: &str,
        userpass: &str,
    ) -> Result<(), MensagoError> {
        if !self.is_connected() {
            return Err(MensagoError::ErrNotConnected);
        }

        let profile = match self.pman.get_active_profile() {
            Some(v) => v,
            None => return Err(MensagoError::ErrNoProfile),
        };

        // The domain for a profile will be non-None if there is already an identity workspace
        // created
        if profile.domain.is_some() {
            return Err(MensagoError::ErrExists);
        }

        let pw = ArgonHash::from(userpass);

        // TODO: use EzNaCl's preferred asymmetric algorithm once implemented
        let devpair = EncryptionPair::generate("CURVE25519")?;

        let reginfo = regcode(
            &mut self.conn,
            address,
            user_regcode,
            &pw,
            profile.devid.as_ref().unwrap(),
            &devpair,
        )?;

        self.setup_workspace(&reginfo)
    }

    /// Create a new user account on the specified server.
    ///
    /// There are a lot of ways this method can fail. It will return ErrNoProfile if a user profile
    /// has not yet been created. ErrExists will be returned if an individual workspace has already
    /// been created in this profile.
    pub fn register(
        &mut self,
        dom: &Domain,
        userpass: &str,
        uid: Option<&UserID>,
    ) -> Result<(), MensagoError> {
        // Process for registration of a new account:

        // Check to see if we already have a workspace allocated on this profile. Because we don't
        // yet support shared workspaces, it means that there are only individual ones right now.
        // Each profile can have only one individual workspace.

        // Check active profile for an existing workspace entry
        // Get the password from the user
        // Check active workspace for device entries. Because we are registering, existing device
        // 	 entries should be removed.
        // Add a device entry to the workspace. This includes both an encryption keypair and
        //   a UUID for the device
        // Connect to requested server
        // Send registration request to server, which requires a hash of the user's supplied
        // 	 password
        // Close the connection to the server
        // If the server returns an error, such as 304 REGISTRATION CLOSED, then return an error.
        // If the server has returned anything else, including a 101 PENDING, begin the
        // 	 client-side workspace information to generate.
        // Generate new workspace data, which includes the associated crypto keys
        // Add the device ID and session to the profile and the server
        // Create, upload, and cross-sign the first keycard entry
        // Create the necessary client-side folders
        // Generate the folder mappings

        // If the server returned 201 REGISTERED, we can proceed with the server-side setup

        // Create the server-side folders based on the mappings on the client side
        // Save all encryption keys into an encrypted 7-zip archive which uses the hash of the
        // user's password has the archive encryption password and upload the archive to the server.

        let profile = match self.pman.get_active_profile() {
            Some(v) => v.clone(),
            None => return Err(MensagoError::ErrNoProfile),
        };

        // The domain for a profile will be non-None if there is already an identity workspace
        // created
        if profile.domain.is_some() {
            return Err(MensagoError::ErrExists);
        }

        if !self.is_connected() {
            self.connect(dom)?;
        }

        let pwhash = ArgonHash::from(userpass);

        // TODO: use EzNaCl's preferred asymmetric algorithm once implemented
        let devpair = EncryptionPair::generate("CURVE25519")?;

        let regdata = register(
            &mut self.conn,
            uid,
            &pwhash,
            profile.devid.as_ref().unwrap(),
            &devpair,
        )?;

        self.setup_workspace(&regdata)?;

        Ok(())
    }

    /// Sets the expiration time limit for new keycard entries. If given a value less than 1, it
    /// will be set to 1, and if greater than 1095 (the maximum as per the spec), it will be set to
    /// 1095.
    #[inline]
    pub fn set_expiration(&mut self, days: u16) {
        self.expiration = match days {
            v if v < 1 => 1,
            v if v > 1095 => 1095,
            v => v,
        };
    }

    /// Creates a new entry in the user's keycard. New keys are created and added to the database.
    pub fn update_keycard(&mut self) -> Result<(), MensagoError> {
        if !self.is_connected() {
            return Err(MensagoError::ErrNotConnected);
        }
        if !self.is_logged_in() {
            return Err(MensagoError::ErrNoLogin);
        }

        let profile = match self.pman.get_active_profile_mut() {
            Some(v) => v,
            None => return Err(MensagoError::ErrNoProfile),
        };

        // Some extra variables to quiet the borrow checker
        let waddr = profile.get_waddress().unwrap().clone();
        let domstr = profile.domain.as_ref().unwrap().to_string();
        let uid = profile.uid.clone();
        let profname = profile.name.clone();

        let mgmtrec = get_mgmt_record(profile.domain.as_ref().unwrap(), self.dns.as_mut())?;
        let ovkey = VerificationKey::from(&mgmtrec.pvk);

        let db = profile.get_db()?;
        let cardopt = get_card_from_db(db, &waddr.as_string(), EntryType::User, false)?;

        if cardopt.is_some() {
            let mut card = cardopt.unwrap();
            card.verify()?;
            let cstemp = get_keypair_by_category(db, &KeyCategory::ConReqSigning)?;
            let crspair = match SigningPair::from(&cstemp[0], &cstemp[1]) {
                Ok(v) => v,
                Err(e) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "BUG: bad CR signing pair obtained in update_keycard: {}",
                        e
                    )))
                }
            };

            let keys = card.chain(&crspair, self.expiration)?;

            let mut entry = card.get_current_mut().unwrap();
            addentry(&mut self.conn, &mut entry, &ovkey, &crspair)?;

            add_keypair(
                db,
                &waddr,
                &keys["crsigning.public"],
                &keys["crsigning.private"],
                get_preferred_hash_algorithm(self.use_certified),
                &KeyType::SigningKey,
                &KeyCategory::ConReqSigning,
            )?;
            add_keypair(
                db,
                &waddr,
                &keys["crencryption.public"],
                &keys["crencryption.private"],
                get_preferred_hash_algorithm(self.use_certified),
                &KeyType::AsymEncryptionKey,
                &KeyCategory::ConReqEncryption,
            )?;
            add_keypair(
                db,
                &waddr,
                &keys["signing.public"],
                &keys["signing.private"],
                get_preferred_hash_algorithm(self.use_certified),
                &KeyType::SigningKey,
                &KeyCategory::Signing,
            )?;
            add_keypair(
                db,
                &waddr,
                &keys["encryption.public"],
                &keys["encryption.private"],
                get_preferred_hash_algorithm(self.use_certified),
                &KeyType::AsymEncryptionKey,
                &KeyCategory::Encryption,
            )?;

            // return update_keycard_in_db(db, card.as_ref().unwrap(), false);
            return update_keycard_in_db(db, &card, false);
        };

        // `card` is none, so it means that we need to create a new root keycard entry for the user.
        // We also don't need to generate any new keys because that was done when the workspace was
        // provisioned -- just pull them from the database and go. :)
        let cstemp = get_keypair_by_category(db, &KeyCategory::ConReqSigning)?;
        let crspair = match SigningPair::from(&cstemp[0], &cstemp[1]) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "BUG: bad CR signing pair obtained in update_keycard: {}",
                    e
                )))
            }
        };

        let crekey =
            match EncryptionKey::from(&get_key_by_category(db, &KeyCategory::ConReqEncryption)?) {
                Ok(v) => v,
                Err(e) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "BUG: bad CR encryption key obtained in update_keycard: {}",
                        e
                    )))
                }
            };

        let ekey = match EncryptionKey::from(&get_key_by_category(db, &KeyCategory::Encryption)?) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "BUG: bad encryption key obtained in update_keycard: {}",
                    e
                )))
            }
        };

        let vkey = match EncryptionKey::from(&get_key_by_category(db, &KeyCategory::Signing)?) {
            Ok(v) => v,
            Err(e) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "BUG: bad verification key obtained in update_keycard: {}",
                    e
                )))
            }
        };

        let mut entry = Entry::new(EntryType::User).unwrap();
        entry.set_fields(&vec![
            (String::from("Index"), String::from("1")),
            (String::from("Name"), profname),
            (String::from("Workspace-ID"), waddr.get_wid().to_string()),
            (String::from("Domain"), domstr),
            (
                String::from("Contact-Request-Verification-Key"),
                crspair.get_public_str(),
            ),
            (
                String::from("Contact-Request-Encryption-Key"),
                crekey.get_public_str(),
            ),
            (String::from("Encryption-Key"), ekey.get_public_str()),
            (String::from("Verification-Key"), vkey.get_public_str()),
        ])?;

        if uid.is_some() {
            entry.set_field("User-ID", uid.as_ref().unwrap().to_string().as_str())?;
        }

        // We don't worry about checking entry compliance because addentry() handles it
        addentry(&mut self.conn, &mut entry, &ovkey, &crspair)?;

        let mut card = Keycard::new(EntryType::User);
        card.entries.push(entry);
        update_keycard_in_db(db, &card, false)
    }

    /// Internal method which finishes all the profile and workspace setup common to standard
    /// registration and registration via a code.
    fn setup_workspace(&mut self, reginfo: &RegInfo) -> Result<(), MensagoError> {
        let profile = match self.pman.get_active_profile_mut() {
            Some(v) => v,
            None => return Err(MensagoError::ErrNoProfile),
        };

        let mut w = Workspace::new(&profile.path);
        let db = profile.get_db()?;
        w.generate(
            db,
            reginfo.uid.as_ref(),
            &reginfo.domain,
            &reginfo.wid,
            &reginfo.password.to_string(),
        )?;

        profile.set_identity(w, &reginfo.password)?;

        let db = profile.get_db()?;

        let tempname = match hostname::get() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrIO(e.to_string())),
        };
        let devicename = tempname.to_string_lossy();
        add_device_session(
            db,
            &WAddress::from_parts(&reginfo.wid, &reginfo.domain),
            &reginfo.devid,
            &reginfo.devpair,
            Some(&devicename),
        )

        // NOTE: we do not update the keycard here because the caller needs to do this. The user
        // may need/want to set their name information for their keycard and this must be done
        // dealing with their keycard
    }

    // TODO: Finish implementing Client class.
}

/// Returns the default location for Mensago profiles for the current user. On Windows, this is
/// in `AppData\Local\mensago` in the user's home directory. For everything else, it is at
/// `~/mensago`. If, for some bizarre reason, this function cannot determine the home directory of
/// the current user, it returns None.
pub fn get_default_profile_path() -> Option<PathBuf> {
    let mut home = match home_dir() {
        Some(v) => v,
        None => return None,
    };

    if env::consts::OS == "windows" {
        home.push("AppData\\Local\\mensago");
    } else {
        home.push(".mensago");
    }

    Some(home)
}
