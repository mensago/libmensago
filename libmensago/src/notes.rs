use crate::base::MensagoError;
use crate::contacts::DBModel;
use libkeycard::{RandomID, Timestamp};
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
    pub name: String,
    pub mimetype: Mime,
    pub data: Vec<u8>,
}

impl AttachmentModel {
    /// Creates a new empty AttachmentModel
    pub fn new() -> AttachmentModel {
        AttachmentModel {
            id: RandomID::generate(),
            name: String::new(),
            mimetype: Mime::from_str("application/octet-stream").unwrap(),
            data: Vec::new(),
        }
    }

    /// Creates a new AttachmentModel from raw, unencoded data
    pub fn from_raw(name: &str, mimetype: &Mime, data: &[u8]) -> AttachmentModel {
        AttachmentModel {
            id: RandomID::generate(),
            name: String::from(name),
            mimetype: mimetype.clone(),
            data: data.to_vec(),
        }
    }

    /// `load_from_db()` instantiates an AttachmentModel from the specified file ID.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<AttachmentModel, MensagoError> {
        let mut out: AttachmentModel;

        let mut stmt = conn.prepare("SELECT name,mimetype,data FROM attachments WHERE id = ?1")?;
        let (name, mimestr, attdata) = match stmt.query_row(&[&id.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, Vec<u8>>(2).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };
        drop(stmt);

        let atttype = match Mime::from_str(&mimestr) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad attachment MIME type received from database: '{}'",
                    mimestr
                )))
            }
        };

        out = AttachmentModel::from_raw(&name, &atttype, &attdata);
        out.id = id.clone();

        Ok(out)
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
            "INSERT OR REPLACE INTO attachments(id,name,mimetype,data) VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                &self.id.to_string(),
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
    created: Timestamp,
    updated: Timestamp,
    format: NoteFormat,
    title: String,
    body: String,
    tags: Vec<String>,
    group: String,
    attachments: Vec<AttachmentModel>,
}
