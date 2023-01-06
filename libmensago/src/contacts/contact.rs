use crate::base::*;
use crate::contacts::*;
use crate::dbconn::*;
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
        if self.annotations.is_none() {
            self.annotations = Some(ContactDataModel::new("", self.data.entity_type, true, None))
        }
    }

    /// Returns the IDs of all contacts in the database.
    ///
    /// Because file attachments can make ContactDataModels very large and a user may have thousands of
    /// contacts, this method and `get_names()` are the two ways of getting information
    /// about all of the user's contacts at once and dealing with them iteratively. Generally
    /// speaking, you probably want `get_names()`.
    pub fn get_ids(conn: &mut DBConn) -> Result<Vec<RandomID>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();

        let rows = conn.query("SELECT id FROM contacts", [])?;
        if rows.len() == 0 {
            return Err(MensagoError::ErrNotFound);
        }
        for row in rows {
            if row.len() != 1 || row[0].get_type() != DBValueType::Text {
                return Err(MensagoError::ErrSchemaFailure);
            }

            let conid = match RandomID::from(&row[0].to_string()) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact model ID {} in contacts",
                        row[0]
                    )))
                }
            };
            ids.push(conid);
        }

        Ok(ids)
    }

    /// This convenience method returns a list of NameModels representing all the user's contacts.
    ///
    /// Because file attachments can make ContactDataModels very large and a user may have thousands of
    /// contacts, this method and `get_ids()` are the two ways of getting information about all of
    /// the user's contacts at once and dealing with them iteratively.
    #[inline]
    pub fn get_names(conn: &mut DBConn) -> Result<Vec<NameModel>, MensagoError> {
        let mut out = Vec::<NameModel>::new();

        for id in Contact::get_ids(conn)? {
            out.push(NameModel::load_from_db(&id, conn)?)
        }
        Ok(out)
    }
}
