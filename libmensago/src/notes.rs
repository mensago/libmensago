use crate::base::MensagoError;
use libkeycard::Timestamp;
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

/// Attachment is a generic data class for housing file attachments.
#[derive(Debug, PartialEq, Clone)]
pub struct Attachment {
    name: String,
    mimetype: Mime,
    encoding: BinEncoding,
    id: String,
    data: String,
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
    attachments: Vec<Attachment>,
}
