use crate::base::*;
use libkeycard::*;
use mime::Mime;
use rusqlite;
use std::fmt;
use std::str::FromStr;

pub trait DBModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
}

/// SeparatedStrList represents a group of strings which are separated by a string of some type,
/// e.g. a comma, a colon, etc. The separator may be more than one character, but regardless of the
/// separator, items in the list may not contain the string used as the separator.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct SeparatedStrList {
    separator: String,
    pub items: Vec<String>,
}

impl SeparatedStrList {
    /// Creates a new instance with the specified separator
    pub fn new(sep: &str) -> SeparatedStrList {
        SeparatedStrList {
            separator: String::from(sep),
            items: Vec::new(),
        }
    }

    pub fn from(s: &str, sep: &str) -> SeparatedStrList {
        if sep.len() == 0 {
            return SeparatedStrList {
                separator: String::new(),
                items: vec![String::from(s)],
            };
        }

        SeparatedStrList {
            separator: String::from(sep),
            items: SeparatedStrList::parse(s, sep),
        }
    }

    /// Returns all items in the list joined by the instance's separator character. No padding is
    /// placed between the items and the separator character. If there are no items in the list,
    /// this method returns an empty string.
    pub fn join(&self) -> String {
        if self.items.len() > 0 {
            self.items.join(&self.separator)
        } else {
            String::new()
        }
    }

    /// `push()` appends a string to the list. This can append one item at a time or it can append
    /// multiple items if given a string containing the separator.
    pub fn push(&mut self, s: &str) -> &mut Self {
        self.items
            .append(&mut SeparatedStrList::parse(s, &self.separator));
        self
    }

    /// `set()` replaces the contents of the list with that of the given string.
    pub fn set(&mut self, s: &str) -> &mut Self {
        self.items.clear();
        self.push(s)
    }

    pub fn set_separator(&mut self, sep: &str) -> &mut Self {
        self.separator = String::from(sep);
        self
    }

    /// Private method which handles separation and formatting.
    /// Remember, kids, Don't Repeat Yourself! 😛
    fn parse(s: &str, sep: &str) -> Vec<String> {
        s.split(&sep)
            .map(|x| x.trim())
            .filter(|x| x.len() > 0)
            .map(|x| String::from(x))
            .collect()
    }
}

impl fmt::Display for SeparatedStrList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.items.len() > 0 {
            write!(f, "{}", self.items.join(&self.separator))
        } else {
            write!(f, "")
        }
    }
}

/// AttachmentModel is a generic data class for housing file attachments.
#[derive(Debug, PartialEq, Clone)]
pub struct AttachmentModel {
    pub id: RandomID,
    pub docid: RandomID,
    pub name: String,
    pub mimetype: Mime,
    pub data: Vec<u8>,
}

impl AttachmentModel {
    /// Creates a new empty AttachmentModel
    pub fn new(docid: &RandomID) -> AttachmentModel {
        AttachmentModel {
            id: RandomID::generate(),
            docid: docid.clone(),
            name: String::new(),
            mimetype: Mime::from_str("application/octet-stream").unwrap(),
            data: Vec::new(),
        }
    }

    /// Creates a new AttachmentModel from raw, unencoded data
    pub fn from_raw(docid: &RandomID, name: &str, mimetype: &Mime, data: &[u8]) -> AttachmentModel {
        AttachmentModel {
            id: RandomID::generate(),
            docid: docid.clone(),
            name: String::from(name),
            mimetype: mimetype.clone(),
            data: data.to_vec(),
        }
    }

    /// `load_from_db()` instantiates an AttachmentModel from the specified file ID and owning
    /// document ID.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<AttachmentModel, MensagoError> {
        let mut out: AttachmentModel;

        let mut stmt =
            conn.prepare("SELECT docid,name,mimetype,data FROM attachments WHERE id = ?1")?;
        let (docidstr, name, mimestr, attdata) = match stmt.query_row(&[&id.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, String>(2).unwrap(),
                row.get::<usize, Vec<u8>>(3).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };
        drop(stmt);

        let docid = match RandomID::from(&docidstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad document ID received from database: '{}'",
                    docidstr
                )))
            }
        };

        let atttype = match Mime::from_str(&mimestr) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad attachment MIME type received from database: '{}'",
                    mimestr
                )))
            }
        };

        out = AttachmentModel::from_raw(&docid, &name, &atttype, &attdata);
        out.id = id.clone();

        Ok(out)
    }

    /// Returns a list of all AttachmentModels that belong to a specific contact.
    pub fn load_all(
        docid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<AttachmentModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();

        let mut stmt = match conn.prepare("SELECT id FROM attachments WHERE docid = ?1") {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut rows = match stmt.query([&docid.as_string()]) {
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
                        "Bad attachment model ID {} in attachments",
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
        drop(rows);
        drop(stmt);

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(AttachmentModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }

    /// Removes all of a document's AttachmentModels from the database
    pub fn delete_all(
        docid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM attachments WHERE docid=?1",
            &[&docid.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

impl DBModel for AttachmentModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM attachments WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        {
            let mut stmt =
                conn.prepare("SELECT name,mimetype,data FROM attachments WHERE id = ?1")?;
            let (name, mimestr, attdata) = match stmt.query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, Vec<u8>>(2).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let atttype = match Mime::from_str(&mimestr) {
                Ok(v) => v,
                Err(_) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad attachment MIME type received from database: '{}'",
                        mimestr
                    )))
                }
            };

            self.name = name;
            self.mimetype = atttype;
            self.data = attdata;
        }
        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO attachments(id,docid,name,mimetype,data) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![
                &self.id.to_string(),
                &self.docid.to_string(),
                &self.name,
                &self.mimetype.to_string(),
                &self.data,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{dbsupport::SeparatedStrList, MensagoError};

    #[test]
    fn test_seplist() -> Result<(), MensagoError> {
        // Empty item filtering
        assert_eq!(
            SeparatedStrList::from("a::b::c::d::", "::").join(),
            "a::b::c::d"
        );

        // Duplicate separator filtering
        assert_eq!(
            SeparatedStrList::from("a::b::c::::::d::", "::").join(),
            "a::b::c::d"
        );

        // set()/set_separator()
        assert_eq!(
            SeparatedStrList::from("a:b:c:d:", ":")
                .set_separator("-")
                .set("a::b")
                .join(),
            "a::b"
        );

        // push()
        assert_eq!(
            SeparatedStrList::from("a:b:c:d:", ":")
                .set_separator("-")
                .push("e::f")
                .join(),
            "a-b-c-d-e::f"
        );

        // Empty string handling
        assert_eq!(SeparatedStrList::from("", ":").join().len(), 0);

        Ok(())
    }
}
