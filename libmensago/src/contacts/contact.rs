use crate::base::*;
use crate::contacts::*;
use libkeycard::*;

/// Contact represents a complete contact, including annotations
pub struct Contact {
    pub data: ContactDataModel,
    pub annotations: Option<ContactDataModel>,
}

impl Contact {
    /// Returns a new Contact without annotations
    pub fn new(name: &str, etype: EntityType) -> Contact {
        Contact {
            data: ContactDataModel::new(name, etype, false, None),
            annotations: None,
        }
    }

    /// Returns true if the model has client-side annotations
    pub fn has_annotations(&self) -> bool {
        self.annotations.is_some()
    }

    /// Ensures that the contact has a data container for annotations
    pub fn enable_annotations(&mut self) {
        // TODO: implement enable_annotations()
    }

    /// Returns the IDs of all contacts in the database.
    ///
    /// Because file attachments can make ContactDataModels very large and a user may have thousands of
    /// contacts, this method and `get_names()` are the two ways of getting information
    /// about all of the user's contacts at once and dealing with them iteratively. Generally
    /// speaking, you probably want `get_names()`.
    pub fn get_ids(conn: &mut rusqlite::Connection) -> Result<Vec<RandomID>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();

        let mut stmt = match conn.prepare("SELECT id FROM contacts") {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut rows = match stmt.query([]) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        while option_row.is_some() {
            let row = option_row.unwrap();
            let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact model ID {} in contacts",
                        &row.get::<usize, String>(0).unwrap()
                    )))
                }
            };
            ids.push(partid);

            option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        }

        Ok(ids)
    }

    /// This convenience method returns a list of NameModels representing all the user's contacts.
    ///
    /// Because file attachments can make ContactDataModels very large and a user may have thousands of
    /// contacts, this method and `get_ids()` are the two ways of getting information about all of
    /// the user's contacts at once and dealing with them iteratively.
    #[inline]
    pub fn get_names(conn: &mut rusqlite::Connection) -> Result<Vec<NameModel>, MensagoError> {
        let mut out = Vec::<NameModel>::new();

        for id in Contact::get_ids(conn)? {
            out.push(NameModel::load_from_db(&id, conn)?)
        }
        Ok(out)
    }
}
