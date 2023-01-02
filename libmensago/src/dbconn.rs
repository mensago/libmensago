//! This module exists primarily because of SQLite3's hook function model, which is pretty clunky
//! for our needs: a firehose of change notifications. This module defines a pubsub event dispatcher
//! so that clients don't have to do all the filtering. It also exists because the rusqlite module
//! is painful to use and this attempts to make database interactions less so.

use rusqlite;
use std::fmt;
use std::path::PathBuf;
use std::sync::Mutex;

/// The DBConn type is a thread-safe shared connection to an SQLite3 database.
#[derive(Debug)]
pub struct DBConn {
    db: Mutex<Option<rusqlite::Connection>>,

    // Yes, POSIX non-UTF8 paths. If someone has a non-UTF8 path in their *NIX box, they can fix
    // their paths or go pound sand.
    path: String,
}

impl fmt::Display for DBConn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.path.len() > 0 {
            write!(f, "DBConn: {}", self.path)
        } else {
            write!(f, "DBConn: <disconnected>")
        }
    }
}

impl DBConn {
    /// get_path() returns a string containing the path to the database or an empty string if the
    /// object is not connected to any database.
    pub fn get_path(&self) -> &str {
        return &self.path;
    }

    /// connect() sets up a connection to a SQLite3 database, given a path. If there is already a
    /// connection in place, this call will return an error. It is the caller's reponsibility to
    /// ensure that there are not multiple callers which still depend on the connection and
    /// disconnect the instance at that time.
    pub fn connect(&self, path: &PathBuf) -> Result<(), rusqlite::Error> {
        // TODO: finish connect()

        // let db = self.db.lock().unwrap();

        // let db = match rusqlite::Connection::open_with_flags(
        //     path,
        //     rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        // ) {
        //     Ok(v) => v,
        //     Err(e) => return Err(e),
        // };

        Ok(())
    }

    /// execute() runs a SQL statement, taking a string containing the SQL command and a Vec! of any
    /// parameters
    pub fn execute<P: rusqlite::Params>(cmd: &str, params: P) {}
}

// Event Types
pub enum DBEvent {
    /// Received when a specific item in a row is changed
    Update,

    /// Received when items are added to or deleted from a table
    Insert,
    Delete,
}

// Event Channels
pub enum DBChannel {
    Messages,
    Contacts,
    Schedule,
    Tasks,
    Notes,
}
