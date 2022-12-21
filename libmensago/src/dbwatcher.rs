use lazy_static::lazy_static;
use libkeycard::RandomID;
use rusqlite;

//! This module exists because of SQLite3's hook function model, which is pretty clunky for our
//! needs: a firehose of change notifications. This module defines a pubsub event dispatcher so that
//! clients don't have to do all the filtering. It has a limited scope, however.

// lazy_static! {
//     // Number of seconds to wait for a client before timing out
//     static ref CONN_TIMEOUT: Duration = Duration::from_secs(1800);
// }

// Event Types
pub enum DBEvent {
	/// Received when a specific item in a row is changed
	Update,

	/// Received when items are added to or deleted from a table
	Insert,
	Delete,
}

struct DBDispatcher {
	db: rusqlite::Connection,
}

/// Subscribes to updates on a specific table.
pub fn listen_table(name: &str) {}

/// Unsubscribes from updates on a specific table
pub fn unlisten_table() {}

/// Subscribes to changes to an item
pub fn listen_item(table: &str) {}

/// Unsubscribes from changes to an item
pub fn unlisten_item() {}

// TODO: Finish DBDispatcher code