use crate::{base::MensagoError, dbconn::*, dbsupport::*, types::DocFormat};
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
    pub fn load_from_db(id: &RandomID, conn: &mut DBConn) -> Result<NoteModel, MensagoError> {
        let values = conn.query(
            "SELECT title,format,body,created,updated,notebook,tags FROM notes WHERE id = ?1",
            &[&id.to_string()],
        )?;
        if values.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if values[0].len() != 7 {
            return Err(MensagoError::ErrSchemaFailure);
        }
        let title = values[0][0].to_string();
        let formatstr = values[0][1].to_string();
        let body = values[0][2].to_string();
        let createdstr = values[0][3].to_string();
        let updatedstr = values[0][4].to_string();
        let notebook = values[0][5].to_string();
        let tagstr = values[0][6].to_string();

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
    pub fn update_title(&mut self, conn: &mut DBConn, text: &str) -> Result<(), MensagoError> {
        // Empty titles are not permitted
        if text.len() < 1 {
            return Err(MensagoError::ErrEmptyData);
        }

        self.title = String::from(text);
        self.updated = Timestamp::new();

        conn.execute(
            "UPDATE notes SET title=?1,updated=?2 WHERE id=?3",
            [
                &self.title.to_string(),
                &self.updated.to_string(),
                &self.id.to_string(),
            ],
        )
    }

    /// update_text() updates the text in the NoteModel and ensures the corresponding database row
    /// is current.
    pub fn update_text(&mut self, conn: &mut DBConn, text: &str) -> Result<(), MensagoError> {
        self.body = String::from(text);
        self.updated = Timestamp::new();

        conn.execute(
            "UPDATE notes SET body=?1,updated=?2 WHERE id=?3",
            rusqlite::params![
                &self.body.to_string(),
                &self.updated.to_string(),
                &self.id.to_string(),
            ],
        )
    }
}

impl DBModel for NoteModel {
    fn delete_from_db(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
        match conn.execute("DELETE FROM notes WHERE id=?1", &[&self.id.to_string()]) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        AttachmentModel::delete_all(&self.id, conn)?;

        Ok(())
    }

    fn refresh_from_db(&mut self, conn: &mut DBConn) -> Result<(), MensagoError> {
        let values = conn.query(
            "SELECT title,format,body,created,updated,notebook,tags FROM notes WHERE id = ?1",
            &[&self.id.to_string()],
        )?;
        if values.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if values[0].len() != 7 {
            return Err(MensagoError::ErrSchemaFailure);
        }
        let title = values[0][0].to_string();
        let formatstr = values[0][1].to_string();
        let body = values[0][2].to_string();
        let createdstr = values[0][3].to_string();
        let updatedstr = values[0][4].to_string();
        let notebook = values[0][5].to_string();
        let tagstr = values[0][6].to_string();

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

    fn set_in_db(&self, conn: &mut DBConn) -> Result<(), MensagoError> {
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
pub fn get_notebooks(conn: &mut DBConn) -> Result<Vec<String>, MensagoError> {
    let rows = conn.query("SELECT DISTINCT notebook FROM notes", [])?;
    if rows.len() == 0 {
        return Err(MensagoError::ErrNotFound);
    }

    let mut out = Vec::<String>::new();
    for row in rows {
        if row.len() != 1 || row[0].get_type() != DBValueType::Text {
            return Err(MensagoError::ErrSchemaFailure);
        }

        out.push(row[0].to_string());
    }

    Ok(out)
}

/// Returns a list of basic note information for the specified group. If given an empty string,
/// all notes in the database are returned.
pub fn get_notes(conn: &mut DBConn, notebook: &str) -> Result<Vec<NotebookItem>, MensagoError> {
    let rows = conn.query(
        "SELECT rowid,id,title FROM notes WHERE notebook = ?1",
        [notebook],
    )?;
    if rows.len() == 0 {
        return Err(MensagoError::ErrNotFound);
    }

    let mut out = Vec::<NotebookItem>::new();
    for row in rows {
        if row.len() != 3
            || row[0].get_type() != DBValueType::Integer
            || row[1].get_type() != DBValueType::Text
            || row[2].get_type() != DBValueType::Text
        {
            return Err(MensagoError::ErrSchemaFailure);
        }

        let noteid = match RandomID::from(&row[1].to_string()) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad note ID {} in notes",
                    row[0]
                )))
            }
        };
        out.push(NotebookItem {
            rowid: row[0].to_int().unwrap() as usize,
            id: noteid,
            title: row[2].to_string(),
        });
    }

    Ok(out)
}
