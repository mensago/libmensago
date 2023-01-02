//! This module exists primarily because of SQLite3's hook function model, which is pretty clunky
//! for our needs: a firehose of change notifications. This module defines a pubsub event dispatcher
//! so that clients don't have to do all the filtering. It also exists because the rusqlite module
//! is painful to use and this attempts to make database interactions less so.

use crate::base::MensagoError;
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
    pub fn connect(&mut self, path: &PathBuf) -> Result<(), MensagoError> {
        let mut connhandle = self.db.lock().unwrap();
        if (*connhandle).is_some() {
            return Err(MensagoError::ErrExists);
        }

        *connhandle = match rusqlite::Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(v) => Some(v),
            Err(e) => return Err(MensagoError::RusqliteError(e)),
        };

        self.path = match path.to_str() {
            Some(v) => String::from(v),
            None => return Err(MensagoError::ErrPathUTF8),
        };

        Ok(())
    }

    /// disconnect() disconnects from the SQLite3 database. If already disconnected, this will not
    /// return an error.
    pub fn disconnect(&mut self) -> Result<(), MensagoError> {
        let mut connhandle = self.db.lock().unwrap();
        if (*connhandle).is_none() {
            return Ok(());
        }

        // Calling close() is functionally equivalent to calling the drop(), so we're just going
        // to assign None to close the db connection
        *connhandle = None;

        Ok(())
    }

    /// execute() runs a SQL statement, taking a string containing the SQL command and a Vec! of any
    /// parameters
    pub fn execute<P: rusqlite::Params>(
        &mut self,
        cmd: &str,
        params: P,
    ) -> Result<(), MensagoError> {
        let connhandle = self.db.lock().unwrap();
        if (*connhandle).is_none() {
            return Err(MensagoError::ErrNoInit);
        }

        let conn = connhandle.as_ref().unwrap();
        match conn.execute(cmd, params) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::RusqliteError(e)),
        }
    }

    /// query_row() executes a query intended to only return one row of results.
    pub fn query_row<P: rusqlite::Params>(
        &mut self,
        cmd: &str,
        params: P,
    ) -> Result<Vec<String>, MensagoError> {
        let connhandle = self.db.lock().unwrap();
        if (*connhandle).is_none() {
            return Err(MensagoError::ErrNoInit);
        }

        let conn = connhandle.as_ref().unwrap();
        let mut stmt = conn.prepare(cmd)?;

        let out = stmt.query_row(params, |row| {
            let mut valuelist = Vec::new();

            let mut i = 0;
            while let Ok(rowval) = row.get::<usize, String>(i) {
                valuelist.push(rowval);
                i += 1;
            }

            Ok(valuelist)
        })?;

        Ok(out)
    }

    /// query_row() executes a query intended to only return one row of results.
    pub fn query<P: rusqlite::Params>(
        &mut self,
        cmd: &str,
        params: P,
    ) -> Result<Vec<Vec<String>>, MensagoError> {
        let connhandle = self.db.lock().unwrap();
        if (*connhandle).is_none() {
            return Err(MensagoError::ErrNoInit);
        }

        let conn = connhandle.as_ref().unwrap();
        let mut stmt = conn.prepare(cmd)?;

        // Queries with rusqlite are extremely ugly because the results wrapped several layers
        // deep. The query() call returns a Result containing a Rows() structure. If we get an
        // error here, there was a problem either with the query or the database.
        let mut rows = match stmt.query(params) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::RusqliteError(e)),
        };

        // The Rows::next() call returns Result<Some<Result<Row>>>. Seriously. The possible
        // return values are:
        //
        // Err() -> an error occurred getting the next row
        // Ok(Some(Row)) -> another row was returned
        // Ok(None) -> all results have been returned

        let mut option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::RusqliteError(e)),
        };

        let mut out = Vec::new();
        while option_row.is_some() {
            let row = option_row.unwrap();

            let mut valuelist = Vec::new();

            let mut i = 0;
            while let Ok(rowval) = row.get::<usize, String>(i) {
                valuelist.push(rowval);
                i += 1;
            }
            out.push(valuelist);

            option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::RusqliteError(e)),
            };
        }

        Ok(out)
    }
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
