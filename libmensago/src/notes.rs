use crate::base::MensagoError;
use crate::dbsupport::DBModel;
use crate::dbsupport::SeparatedStrList;
use libkeycard::*;
use mime::Mime;
use std::fmt;
use std::str::FromStr;

/// The BinEncoding type is for the type of binary-to-text encoding used
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum BinEncoding {
    Base64,
    Base85,
}

impl fmt::Display for BinEncoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BinEncoding::Base64 => write!(f, "base64"),
            BinEncoding::Base85 => write!(f, "base85"),
        }
    }
}

impl FromStr for BinEncoding {
    type Err = ();

    fn from_str(input: &str) -> Result<BinEncoding, Self::Err> {
        match input.to_lowercase().as_str() {
            "base64" => Ok(BinEncoding::Base64),
            "base85" => Ok(BinEncoding::Base85),
            _ => Err(()),
        }
    }
}

impl std::convert::TryFrom<&str> for BinEncoding {
    type Error = MensagoError;
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        match input.to_lowercase().as_str() {
            "base64" => Ok(BinEncoding::Base64),
            "base85" => Ok(BinEncoding::Base85),
            _ => Err(MensagoError::ErrBadValue),
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

/// NoteFormat indicates the type of format used in a note -- plain text or SFTM.
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum NoteFormat {
    Text,
    SFTM,
}

impl fmt::Display for NoteFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NoteFormat::Text => write!(f, "text"),
            NoteFormat::SFTM => write!(f, "sftm"),
        }
    }
}

impl FromStr for NoteFormat {
    type Err = ();

    fn from_str(input: &str) -> Result<NoteFormat, Self::Err> {
        match input.to_lowercase().as_str() {
            "text" => Ok(NoteFormat::Text),
            "sftm" => Ok(NoteFormat::SFTM),
            _ => Err(()),
        }
    }
}

impl std::convert::TryFrom<&str> for NoteFormat {
    type Error = MensagoError;
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        match input.to_lowercase().as_str() {
            "text" => Ok(NoteFormat::Text),
            "sftm" => Ok(NoteFormat::SFTM),
            _ => Err(MensagoError::ErrBadValue),
        }
    }
}

/// The NoteModel type is the data type for managing notes in conjunction with the client database.
#[derive(Debug, PartialEq, Clone)]
pub struct NoteModel {
    pub id: RandomID,
    pub title: String,
    pub format: NoteFormat,
    pub body: String,
    pub created: Timestamp,
    pub updated: Timestamp,
    pub notebook: String,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentModel>,
}

impl NoteModel {
    /// Creates a new empty NoteModel
    pub fn new(title: &str, format: NoteFormat, group: &str) -> NoteModel {
        let ts = Timestamp::new();
        NoteModel {
            id: RandomID::generate(),
            title: String::from(title),
            format,
            body: String::new(),
            created: ts.clone(),
            updated: ts,
            notebook: String::from(group),
            tags: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// `load_from_db()` instantiates an NoteModel from the specified note ID.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<NoteModel, MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT title,format,body,created,updated,notebook,tags FROM notes WHERE id = ?1",
        )?;
        let (title, formatstr, body, createdstr, updatedstr, notebook, tagstr) = match stmt
            .query_row(&[&id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                    row.get::<usize, String>(5).unwrap(),
                    row.get::<usize, String>(6).unwrap(),
                ))
            }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };
        drop(stmt);

        let noteformat = match NoteFormat::from_str(&formatstr) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note format type received from database: '{}'",
                    formatstr
                )))
            }
        };
        let created = match Timestamp::try_from(createdstr.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note creation date received from database: '{}'",
                    createdstr
                )))
            }
        };
        let updated = match Timestamp::try_from(updatedstr.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note updated date received from database: '{}'",
                    updatedstr
                )))
            }
        };

        let taglist = SeparatedStrList::from(&tagstr, ",");

        Ok(NoteModel {
            id: id.clone(),
            title,
            format: noteformat,
            body,
            created,
            updated,
            notebook,
            tags: taglist.items,
            attachments: AttachmentModel::load_all(id, conn)?,
        })
    }
}

impl DBModel for NoteModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute("DELETE FROM notes WHERE id=?1", &[&self.id.to_string()]) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        AttachmentModel::delete_all(&self.id, conn)?;

        Ok(())
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT title,format,body,created,updated,notebook,tags FROM notes WHERE id = ?1",
        )?;
        let (title, formatstr, body, createdstr, updatedstr, notebook, tagstr) = match stmt
            .query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                    row.get::<usize, String>(5).unwrap(),
                    row.get::<usize, String>(6).unwrap(),
                ))
            }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };
        drop(stmt);

        let noteformat = match NoteFormat::from_str(&formatstr) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note format type received from database: '{}'",
                    formatstr
                )))
            }
        };
        let created = match Timestamp::try_from(createdstr.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note creation date received from database: '{}'",
                    createdstr
                )))
            }
        };
        let updated = match Timestamp::try_from(updatedstr.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note updated date received from database: '{}'",
                    updatedstr
                )))
            }
        };

        let taglist = SeparatedStrList::from(&tagstr, ",");

        self.title = title;
        self.format = noteformat;
        self.body = body;
        self.created = created;
        self.updated = updated;
        self.notebook = notebook;
        self.tags = taglist.items;
        self.attachments = AttachmentModel::load_all(&self.id, conn)?;

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO notes(id,title,format,body,created,updated,notebook,tags) 
            VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                &self.id.to_string(),
                &self.title.to_string(),
                &self.format.to_string(),
                &self.body,
                &self.created.to_string(),
                &self.updated.to_string(),
                &self.notebook,
                &self.tags.join(","),
            ],
        ) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        AttachmentModel::delete_all(&self.id, conn)?;
        for item in self.attachments.iter() {
            item.set_in_db(conn)?;
        }
        Ok(())
    }
}
