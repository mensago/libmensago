use crate::{base::MensagoError, dbsupport::*, types::DocFormat};
use libkeycard::*;
use std::fmt;
use std::fs::read_to_string;
use std::path::Path;
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

/// The NoteModel type is the data type for managing notes in conjunction with the client database.
#[derive(Debug, PartialEq, Clone)]
pub struct NoteModel {
    pub id: RandomID,
    pub title: String,
    pub format: DocFormat,
    pub body: String,
    pub created: Timestamp,
    pub updated: Timestamp,
    pub notebook: String,
    pub tags: Vec<String>,
    pub images: Vec<ImageModel>,
    pub attachments: Vec<AttachmentModel>,
}

impl NoteModel {
    /// Creates a new empty NoteModel
    pub fn new(title: &str, format: DocFormat, group: &str) -> NoteModel {
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
            images: Vec::new(),
            attachments: Vec::new(),
        }
    }

    /// `import()` instantiates a NoteModel from a file on disk. Currently only plaintext is
    /// supported, but eventually SFTM support will also be added and possibly even Markdown.
    pub fn import<P: AsRef<Path>>(
        path: P,
        format: DocFormat,
        title: &str,
        notebook: &str,
    ) -> Result<NoteModel, MensagoError> {
        // Very basic format validation. We don't officially support anything beyond plaintext
        // right now, so it's not critical.
        let ext = match path.as_ref().extension() {
            Some(v) => String::from(v.to_string_lossy()),
            None => String::new(),
        };

        match ext.as_str() {
            "md" => {
                if format != DocFormat::Markdown {
                    return Err(MensagoError::ErrTypeMismatch);
                }
            }
            "sdf" => {
                if format != DocFormat::SDF {
                    return Err(MensagoError::ErrTypeMismatch);
                }
            }
            "sftm" => {
                if format != DocFormat::SFTM {
                    return Err(MensagoError::ErrTypeMismatch);
                }
            }
            _ => {
                if format != DocFormat::Text {
                    return Err(MensagoError::ErrTypeMismatch);
                }
            }
        }

        let filedata = match read_to_string(path) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrProgramException(e.to_string())),
        };
        let mut out = NoteModel::new(title, format, notebook);
        out.body = filedata;
        Ok(out)
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

        let docformat = match DocFormat::from_str(&formatstr) {
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
            format: docformat,
            body,
            created,
            updated,
            notebook,
            tags: taglist.items,
            images: ImageModel::load_all(id, conn)?,
            attachments: AttachmentModel::load_all(id, conn)?,
        })
    }

    /// update_title() renames the note ensures the corresponding database row is current.
    pub fn update_title(
        &mut self,
        conn: &mut rusqlite::Connection,
        text: &str,
    ) -> Result<(), MensagoError> {
        // Empty titles are not permitted
        if text.len() < 1 {
            return Err(MensagoError::ErrEmptyData);
        }

        self.title = String::from(text);
        self.updated = Timestamp::new();

        match conn.execute(
            "UPDATE notes SET title=?1,updated=?2 WHERE id=?3",
            rusqlite::params![
                &self.title.to_string(),
                &self.updated.to_string(),
                &self.id.to_string(),
            ],
        ) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        Ok(())
    }

    /// update_text() updates the text in the NoteModel and ensures the corresponding database row
    /// is current.
    pub fn update_text(
        &mut self,
        conn: &mut rusqlite::Connection,
        text: &str,
    ) -> Result<(), MensagoError> {
        self.body = String::from(text);
        self.updated = Timestamp::new();

        match conn.execute(
            "UPDATE notes SET body=?1,updated=?2 WHERE id=?3",
            rusqlite::params![
                &self.title.to_string(),
                &self.updated.to_string(),
                &self.id.to_string(),
            ],
        ) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        Ok(())
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

        let docformat = match DocFormat::from_str(&formatstr) {
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
        self.format = docformat;
        self.body = body;
        self.created = created;
        self.updated = updated;
        self.notebook = notebook;
        self.tags = taglist.items;
        self.images = ImageModel::load_all(&self.id, conn)?;
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

        ImageModel::delete_all(&self.id, conn)?;
        for item in self.images.iter() {
            item.set_in_db(conn)?;
        }

        AttachmentModel::delete_all(&self.id, conn)?;
        for item in self.attachments.iter() {
            item.set_in_db(conn)?;
        }
        Ok(())
    }
}

/// NotebookItem is just a bit of basic high-level information used for notebooks. It contains
/// enough information to display a list of notes in a group and to easily look up the full note
/// when needed.
#[derive(Debug, Clone)]
pub struct NotebookItem {
    // The note's unique rowid for faster database lookups
    pub rowid: usize,
    pub id: RandomID,
    pub title: String,
}

/// Returns a list of the groups of notes in the profile
pub fn get_notebooks(conn: &mut rusqlite::Connection) -> Result<Vec<String>, MensagoError> {
    let mut stmt = match conn.prepare("SELECT DISTINCT notebook FROM notes") {
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

    let mut out = Vec::<String>::new();

    while option_row.is_some() {
        let row = option_row.unwrap();

        out.push(row.get::<usize, String>(0).unwrap());

        option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };
    }

    Ok(out)
}

/// Returns a list of basic note information for the specified group. If given an empty string,
/// all notes in the database are returned.
pub fn get_notes(
    conn: &mut rusqlite::Connection,
    notebook: &str,
) -> Result<Vec<NotebookItem>, MensagoError> {
    let mut stmt = conn.prepare("SELECT rowid,id,title FROM notes WHERE notebook = ?1")?;

    let mut rows = match stmt.query([notebook]) {
        Ok(v) => v,
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    };

    let mut option_row = match rows.next() {
        Ok(v) => v,
        Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
    };

    let mut out = Vec::<NotebookItem>::new();

    while option_row.is_some() {
        let row = option_row.unwrap();

        // let srowid = row.get::<usize, String>(0).unwrap();
        // let rowid = match usize::from_str(&srowid) {
        //     Ok(v) => v,
        //     Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        // };
        let rowid = row.get::<usize, usize>(0).unwrap();
        let snoteid = row.get::<usize, String>(1).unwrap();
        let noteid = match RandomID::from(&snoteid) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note ID in get_notes(): {}",
                    snoteid
                )))
            }
        };
        let title = row.get::<usize, String>(2).unwrap();

        out.push(NotebookItem {
            rowid,
            id: noteid,
            title,
        });

        option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };
    }

    Ok(out)
}
