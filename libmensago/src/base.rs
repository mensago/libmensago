use serde::{Deserialize, Serialize};
use std::fmt;
use std::string;
use thiserror::Error;

/// Type to hold status information from a Mensago protocol command response
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Error)]
pub struct CmdStatus {
    #[serde(rename = "Code")]
    pub code: u16,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Info")]
    pub info: String,
}

impl fmt::Display for CmdStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.info.len() > 0 {
            write!(f, "{}: {} ({})", self.code, self.description, self.info)
        } else {
            write!(f, "{}: {}", self.code, self.description)
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum MensagoError {
    // General error codes
    #[error("Empty data error")]
    ErrEmptyData,
    #[error("Not initialized")]
    ErrNoInit,
    #[error("Non-UTF8 path")]
    ErrPathUTF8,
    #[error("Bad value")]
    ErrBadValue,
    #[error("Resource already exists")]
    ErrExists,
    #[error("Filesystem error")]
    ErrFilesytemError,
    #[error("Not found")]
    ErrNotFound,
    #[error("Reserved")]
    ErrReserved,
    #[error("Type mismatch")]
    ErrTypeMismatch,
    #[error("Unsupported algorithm")]
    ErrUnsupportedAlgorithm,
    #[error("Function unimplemented")]
    ErrUnimplemented,
    #[error("UTF-8 error")]
    ErrUTF8,

    // Client-specific errors
    #[error("No profile")]
    ErrNoProfile,
    #[error("Login required")]
    ErrNoLogin,
    #[error("Admin privileges required")]
    ErrNotAdmin,

    // Network and protocol errors
    #[error("Mensago not available")]
    ErrNoMensago,
    #[error("Invalid frame")]
    ErrInvalidFrame,
    #[error("Invalid size")]
    ErrSize,
    #[error("Bad session")]
    ErrBadSession,
    #[error("Bad message")]
    ErrBadMessage,

    // Database exceptions are *bad*. This is returned only when there is a major problem with the
    // data in the database, such as a workspace having no identity entry.
    #[error("Database exception: {0}")]
    ErrDatabaseException(String),

    // Program exceptions are also extremely bad, but also highly unlikely thanks to Rust
    #[error("Program exception: {0}")]
    ErrProgramException(String),

    // Protocol errors
    #[error(transparent)]
    ErrProtocol(#[from] CmdStatus),
    #[error("schema failure")]
    ErrSchemaFailure,
    #[error("not connected")]
    ErrNotConnected,
    // Server exceptions are returned when the server does something wrong to help troubleshoot
    #[error("Server exception: {0}")]
    ErrServerException(String),
    #[error("Network error")]
    ErrNetworkError,

    // Passthrough errors
    #[error(transparent)]
    EzNaclError(#[from] eznacl::EzNaclError),

    #[error(transparent)]
    LKCError(#[from] libkeycard::LKCError),

    #[error(transparent)]
    RusqliteError(#[from] rusqlite::Error),

    #[error(transparent)]
    Utf8Error(#[from] string::FromUtf8Error),

    // Workaround error codes because these don't implement PartialEq
    #[error("IO error: {0}")]
    ErrIO(String),

    #[error("JSON marshalling error: {0}")]
    SerdeError(String),
}
