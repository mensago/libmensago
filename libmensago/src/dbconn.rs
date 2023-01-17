//! This module exists primarily because of SQLite3's hook function model, which is pretty clunky
//! for our needs: a firehose of change notifications. This module defines a pubsub event dispatcher
//! so that clients don't have to do all the filtering. It also exists because the rusqlite module
//! is painful to use and this attempts to make database interactions less so.

use crate::base::MensagoError;
use crossbeam_channel;
use lazy_static::lazy_static;
use pretty_hex::simple_hex_write;
use rand::{thread_rng, RngCore};

use rusqlite;
use rusqlite::types::*;
use std::{
    collections::HashMap,
    fmt,
    path::PathBuf,
    str,
    sync::{Mutex, RwLock},
};

lazy_static! {
    static ref MESSAGE_SUBSCRIBERS: RwLock<HashMap<u64, crossbeam_channel::Sender<DBUpdate>>> =
        RwLock::new(HashMap::new());
    static ref CONTACT_SUBSCRIBERS: RwLock<HashMap<u64, crossbeam_channel::Sender<DBUpdate>>> =
        RwLock::new(HashMap::new());
    static ref NOTE_SUBSCRIBERS: RwLock<HashMap<u64, crossbeam_channel::Sender<DBUpdate>>> =
        RwLock::new(HashMap::new());
}

/// The DBConn type is a thread-safe shared connection to an SQLite3 database.
#[derive(Debug)]
pub struct DBConn {
    db: Mutex<Option<rusqlite::Connection>>,

    // Yes, I know about POSIX non-UTF8 paths. If someone has a non-UTF8 path in their *NIX box,
    // they can fix their paths or go pound sand.👿
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
    /// Creates a new, empty DBConn instance.
    pub fn new() -> DBConn {
        DBConn {
            db: Mutex::new(None),
            path: String::new(),
        }
    }

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

        *connhandle = match rusqlite::Connection::open(path) {
            Ok(v) => Some(v),
            Err(e) => return Err(MensagoError::RusqliteError(e)),
        };

        (*connhandle).as_mut().unwrap().update_hook(Some(
            move |action: rusqlite::hooks::Action, dbname: &str, tablename: &str, rowid: i64| {
                let dbaction = match action {
                    rusqlite::hooks::Action::SQLITE_INSERT => DBEVENT_INSERT,
                    rusqlite::hooks::Action::SQLITE_UPDATE => DBEVENT_UPDATE,
                    rusqlite::hooks::Action::SQLITE_DELETE => DBEVENT_DELETE,
                    _ => {
                        println!(
                            "BUG: UNKNOWN SQLite action on database {}, table {}, rowid {}",
                            dbname, tablename, rowid
                        );
                        return;
                    }
                };

                // TODO: Reduce copy-paste redundancy in DBConn::connect() once finalized
                match tablename {
                    "messages" => {
                        let handle = MESSAGE_SUBSCRIBERS.write().unwrap();

                        for txpair in &(*handle) {
                            let _ = txpair.1.send(DBUpdate {
                                update: DBUpdateChannel::Messages,
                                event: dbaction,
                                table: String::from(tablename),
                                rowid,
                            });
                        }
                    }
                    "contacts" | "contact_address" | "contact_files" | "contact_keys"
                    | "contact_keyvalue" | "contact_mensago" | "contact_names"
                    | "contact_nameparts" | "contact_photo" => {
                        let handle = CONTACT_SUBSCRIBERS.write().unwrap();

                        for txpair in &(*handle) {
                            let _ = txpair.1.send(DBUpdate {
                                update: DBUpdateChannel::Contacts,
                                event: dbaction,
                                table: String::from(tablename),
                                rowid,
                            });
                        }
                    }
                    "notes" => {
                        let handle = NOTE_SUBSCRIBERS.write().unwrap();

                        for txpair in &(*handle) {
                            let _ = txpair.1.send(DBUpdate {
                                update: DBUpdateChannel::Notes,
                                event: dbaction,
                                table: String::from(tablename),
                                rowid,
                            });
                        }
                    }
                    _ => return,
                };
            },
        ));

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

    /// get_db_value() is a convenience method for when you just want one column value from one row.
    /// Happens more often than you'd think.
    pub fn get_db_value(
        &mut self,
        tablename: &str,
        column: &str,
        idfield: &str,
        id: &str,
    ) -> Result<DBValue, MensagoError> {
        if tablename.len() == 0 || column.len() == 0 || idfield.len() == 0 {
            return Err(MensagoError::ErrEmptyData);
        }

        // Doing regular string substitution in a SQL query is usually a recipe for an injection
        // attack. We're doing this here because (1) using the regular syntax for inserting values
        // into queries creates syntax errors when used for table names and (2) we control that
        // part of the query. We're also doing the same thing for the column because the escaping
        // done for substitution causes the column name to be returned from the query instead of
        // the value of the row in that column. Not great, but it *is* safe in this instance.
        let rows = self.query(
            format!(
                "SELECT {} FROM {} WHERE {} = ?1",
                column, tablename, idfield
            )
            .as_str(),
            [id],
        )?;
        if rows.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if rows[0].len() != 1 {
            return Err(MensagoError::ErrSchemaFailure);
        }

        Ok(rows[0][0].clone())
    }

    /// is_connected() returns true if the instance is connected to a SQLite database
    pub fn is_connected(&self) -> bool {
        let connhandle = self.db.lock().unwrap();
        (*connhandle).is_some()
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

    pub fn exists<P: rusqlite::Params>(
        &mut self,
        cmd: &str,
        params: P,
    ) -> Result<bool, MensagoError> {
        let connhandle = self.db.lock().unwrap();
        if (*connhandle).is_none() {
            return Err(MensagoError::ErrNoInit);
        }

        let conn = connhandle.as_ref().unwrap();
        let mut stmt = conn.prepare(cmd)?;
        match stmt.exists(params) {
            Ok(v) => Ok(v),
            Err(e) => Err(MensagoError::RusqliteError(e)),
        }
    }

    /// query() executes a query intended to only return one row of results.
    pub fn query<P: rusqlite::Params>(
        &mut self,
        cmd: &str,
        params: P,
    ) -> Result<Vec<Vec<DBValue>>, MensagoError> {
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
            while let Ok(rowval) = row.get_ref(i) {
                valuelist.push(DBValue::from(rowval));
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

    /// subscribe() enables realtime notifications for changes made to the database of a specific
    /// type. For performance reason, the updates are filtered to a specific channel, such as
    /// receiving notifications for notes, calendar events, etc. It returns a RandomID used to
    /// identify the subscriber for purposes of unsubscribing from notifications.
    ///
    /// The events parameter is merely a u8 used for bitflags that specify the type of updates to
    /// receive.
    ///
    /// Note that this call does not check to see if the callback is already in the subscriber list
    /// for a particular event channel, so if you add it more than once, you'll get duplicate event
    /// notifications.
    pub fn subscribe(
        &self,
        updtype: DBUpdateChannel,
        tx: crossbeam_channel::Sender<DBUpdate>,
    ) -> Result<u64, MensagoError> {
        // TODO: Reduce copy-paste redundancy in DBConn::subscribe() once finalized
        match updtype {
            DBUpdateChannel::Messages => {
                let mut handle = MESSAGE_SUBSCRIBERS.write().unwrap();

                let mut txid: u64 = 0;
                for _ in 0..10 {
                    let tempid = thread_rng().next_u64();
                    if !handle.contains_key(&tempid) {
                        txid = tempid;
                        break;
                    }
                }

                if txid == 0 {
                    return Err(MensagoError::ErrRNGFail);
                }

                handle.insert(txid, tx.clone());

                Ok(txid)
            }
            DBUpdateChannel::Contacts => {
                let mut handle = CONTACT_SUBSCRIBERS.write().unwrap();

                let mut txid: u64 = 0;
                for _ in 0..10 {
                    let tempid = thread_rng().next_u64();
                    if !handle.contains_key(&tempid) {
                        txid = tempid;
                        break;
                    }
                }

                if txid == 0 {
                    return Err(MensagoError::ErrRNGFail);
                }

                handle.insert(txid, tx.clone());

                Ok(txid)
            }
            DBUpdateChannel::Notes => {
                let mut handle = NOTE_SUBSCRIBERS.write().unwrap();

                let mut txid: u64 = 0;
                for _ in 0..10 {
                    let tempid = thread_rng().next_u64();
                    if !handle.contains_key(&tempid) {
                        txid = tempid;
                        break;
                    }
                }

                if txid == 0 {
                    return Err(MensagoError::ErrRNGFail);
                }

                handle.insert(txid, tx.clone());

                Ok(txid)
            }
        }
    }

    pub fn unsubscribe(channel: DBUpdateChannel, txid: u64) -> Result<(), MensagoError> {
        // TODO: Reduce copy-paste redundancy in DBConn::unsubscribe() once finalized
        match channel {
            DBUpdateChannel::Messages => {
                let mut handle = MESSAGE_SUBSCRIBERS.write().unwrap();
                if !handle.contains_key(&txid) {
                    return Err(MensagoError::ErrNotFound);
                }
                let _ = handle.remove(&txid);
            }
            DBUpdateChannel::Contacts => {
                let mut handle = CONTACT_SUBSCRIBERS.write().unwrap();
                if !handle.contains_key(&txid) {
                    return Err(MensagoError::ErrNotFound);
                }
                let _ = handle.remove(&txid);
            }
            DBUpdateChannel::Notes => {
                let mut handle = NOTE_SUBSCRIBERS.write().unwrap();
                if !handle.contains_key(&txid) {
                    return Err(MensagoError::ErrNotFound);
                }
                let _ = handle.remove(&txid);
            }
        }
        Ok(())
    }
}

pub const DBEVENT_UPDATE: u8 = 0x01;
pub const DBEVENT_INSERT: u8 = 0x02;
pub const DBEVENT_DELETE: u8 = 0x04;
pub const DBEVENT_ALL: u8 = 0x07;

/// Used to request the type of database updates for a particular subscriber
#[derive(Debug, Copy, Clone)]
pub enum DBUpdateChannel {
    Messages,
    Contacts,
    // Schedule,
    // Tasks,
    Notes,
}

/// The DBUpdate structure doesn't contain much -- it doesn't need to. Technically, even the
/// DBChannel property isn't strictly necessary. This structure is intended to be small and sent
/// over subscribers' update channels to be notified when a specific row is modified.
#[derive(Debug, Clone)]
pub struct DBUpdate {
    pub update: DBUpdateChannel,
    pub event: u8,
    pub table: String,
    pub rowid: i64,
}

/// DBValueType makes it easy to tell what type a DBValue has
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DBValueType {
    Text,
    Bool,
    Float,
    Integer,
    Binary,
    Null,
}

impl fmt::Display for DBValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            DBValueType::Text => write!(f, "text"),
            DBValueType::Bool => write!(f, "bool"),
            DBValueType::Float => write!(f, "float"),
            DBValueType::Integer => write!(f, "integer"),
            DBValueType::Binary => write!(f, "binary"),
            DBValueType::Null => write!(f, "null"),
        }
    }
}

/// DBValue is a type which we control that easily maps to rusqlite's Value type, but we will
/// actually own the memory with it and we can add other methods to make working with rusqlite
/// less painful.
#[derive(Debug, Clone, PartialEq)]
pub enum DBValue {
    Text(String),
    Bool(bool),
    Float(f64),
    Integer(i64),
    Binary(Vec<u8>),
    Null,
}

impl From<ValueRef<'_>> for DBValue {
    #[inline]
    fn from(val: ValueRef) -> DBValue {
        match val.data_type() {
            rusqlite::types::Type::Text => DBValue::Text(String::from(val.as_str().unwrap())),
            rusqlite::types::Type::Real => DBValue::Float(val.as_f64().unwrap()),
            rusqlite::types::Type::Integer => DBValue::Integer(val.as_i64().unwrap()),
            rusqlite::types::Type::Blob => DBValue::Binary(val.as_blob().unwrap().to_vec()),
            rusqlite::types::Type::Null => DBValue::Null,
        }
    }
}

impl From<String> for DBValue {
    #[inline]
    fn from(val: String) -> DBValue {
        DBValue::Text(val)
    }
}

impl From<bool> for DBValue {
    #[inline]
    fn from(val: bool) -> DBValue {
        DBValue::Bool(val)
    }
}

impl From<f64> for DBValue {
    #[inline]
    fn from(val: f64) -> DBValue {
        DBValue::Float(val)
    }
}

impl From<isize> for DBValue {
    #[inline]
    fn from(val: isize) -> DBValue {
        DBValue::Integer(val as i64)
    }
}

impl From<i64> for DBValue {
    #[inline]
    fn from(val: i64) -> DBValue {
        DBValue::Integer(val)
    }
}

impl From<Vec<u8>> for DBValue {
    #[inline]
    fn from(data: Vec<u8>) -> DBValue {
        DBValue::Binary(data)
    }
}

impl fmt::Display for DBValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            DBValue::Text(v) => write!(f, "{}", v),
            DBValue::Bool(v) => write!(f, "{}", v.to_string()),
            DBValue::Float(v) => write!(f, "{}", v.to_string()),
            DBValue::Integer(v) => write!(f, "{}", v.to_string()),
            DBValue::Binary(v) => simple_hex_write(f, v),
            DBValue::Null => write!(f, "null"),
        }
    }
}

impl DBValue {
    pub fn get_type(&self) -> DBValueType {
        match *self {
            DBValue::Text(_) => DBValueType::Text,
            DBValue::Bool(_) => DBValueType::Bool,
            DBValue::Float(_) => DBValueType::Float,
            DBValue::Integer(_) => DBValueType::Integer,
            DBValue::Binary(_) => DBValueType::Binary,
            DBValue::Null => DBValueType::Null,
        }
    }

    #[inline]
    pub fn to_bool(&self) -> Option<bool> {
        match self {
            DBValue::Text(v) => Some(v.len() > 0),
            DBValue::Bool(v) => Some(*v),
            DBValue::Float(v) => Some(*v != 0.0),
            DBValue::Integer(v) => Some(*v != 0),
            DBValue::Binary(v) => Some(v.len() > 0),
            DBValue::Null => Some(false),
        }
    }

    #[inline]
    pub fn to_float(&self) -> Option<f64> {
        match self {
            DBValue::Text(_) => None,
            DBValue::Bool(v) => {
                if *v {
                    Some(1.0)
                } else {
                    Some(0.0)
                }
            }
            DBValue::Float(v) => Some(*v),
            DBValue::Integer(v) => Some(*v as f64),
            DBValue::Binary(_) => None,
            DBValue::Null => Some(0.0),
        }
    }

    #[inline]
    pub fn to_int(&self) -> Option<i64> {
        match self {
            DBValue::Text(_) => None,
            DBValue::Bool(v) => {
                if *v {
                    Some(1)
                } else {
                    Some(0)
                }
            }
            DBValue::Float(v) => Some(*v as i64),
            DBValue::Integer(v) => Some(*v),
            DBValue::Binary(_) => None,
            DBValue::Null => Some(0),
        }
    }

    #[inline]
    pub fn to_vec(&self) -> Option<Vec<u8>> {
        match self {
            DBValue::Text(v) => Some(v.as_bytes().to_vec()),
            DBValue::Bool(v) => {
                if *v {
                    Some(vec![1])
                } else {
                    Some(vec![0])
                }
            }
            DBValue::Float(v) => Some(vec![*v as u8]),
            DBValue::Integer(v) => Some(vec![*v as u8]),
            DBValue::Binary(v) => Some(v.clone()),
            DBValue::Null => Some(vec![]),
        }
    }
}
