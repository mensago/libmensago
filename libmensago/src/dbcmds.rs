// This module contains miscellaneous commands related to the local profile database

use crate::{base::MensagoError, dbconn::*};
use chrono::prelude::*;
use libkeycard::*;

/// Obtains a keycard from the database. `owner` is expected to be either a workspace address for a
/// user or a domain for an organization. An error will be returned if something goes wrong in the
/// lookup. A lack of an entry in the database is not considered an error and if no matching
/// keycard exists in the local database, Ok(None) is returned. If managing the user's keycard,
/// check_ttl should be false. It should be set to true only if you are looking to look up a
/// a keycard from the database's cache and need to know if the owning server needs to be queried
/// directly. When check_ttl is true, Ok(None) will be returned if the keycard doesn't exist or if
/// the Time-To-Live has expired.
pub fn get_card_from_db(
    conn: &mut DBConn,
    owner: &str,
    etype: EntryType,
    check_ttl: bool,
) -> Result<Option<Keycard>, MensagoError> {
    let mut card = Keycard::new(etype);

    // This is an internal call and owner has already been validated once, so we don't have to
    // do it again. Likewise, we validate everything ruthlessly when data is brought in, so
    // because that's already been done once, we don't need to do it again here -- just create
    // entries from each row and add them to the card.

    let rows = conn.query(
        "SELECT entry FROM keycards WHERE owner=?1 ORDER BY 'index'",
        [owner],
    )?;
    if rows.len() == 0 {
        return Ok(None);
    }
    for row in rows {
        if row.len() != 1 || row[0].get_type() != DBValueType::Text {
            return Err(MensagoError::ErrSchemaFailure);
        }

        let entry = Entry::from(&row[0].to_string())?;
        card.entries.push(entry);
    }

    if card.entries.len() < 1 {
        return Ok(None);
    }

    if check_ttl {
        let current = card.get_current().unwrap();

        let values = conn.query(
            "SELECT ttlexpires FROM keycards WHERE owner=?1 AND index=?2",
            [&owner, current.get_field("Index").unwrap().as_str()],
        )?;
        if values.len() != 1 {
            return Err(MensagoError::ErrNotFound);
        }
        if values[0].len() != 1 {
            return Err(MensagoError::ErrSchemaFailure);
        }
        let ttlstr = values[0][0].to_string();

        // The only way that the TTL expiration string will be empty is if this belongs to the
        // user's keycard and this never expires.
        if ttlstr.len() == 0 {
            return Ok(Some(card));
        }

        let exptime = match NaiveDate::parse_from_str(&ttlstr, "%Y%m%dT%H%M%SZ") {
            Ok(d) => d,
            Err(e) => {
                // We should never be here
                return Err(MensagoError::ErrProgramException(e.to_string()));
            }
        };

        let now = Utc::now().date_naive();

        if now > exptime {
            return Ok(None);
        }
    }

    Ok(Some(card))
}

/// Adds a keycard to the database's cache or updates it if it already exists. This call is used
/// both for managing the local keycard cache and for managing the user's keycard, which is why
/// the `for_caching` flag exists. If you are managing the user's copy of the local keycard, make
/// sure that for_caching is set to false to ensure that the user's local copy isn't accidentally
/// deleted because its Time-To-Live value expired!
pub fn update_keycard_in_db(
    conn: &mut DBConn,
    card: &Keycard,
    for_caching: bool,
) -> Result<(), MensagoError> {
    let current = match card.get_current() {
        Some(v) => v,
        None => return Err(MensagoError::ErrEmptyData),
    };

    let owner = current.get_owner()?;

    conn.execute("DELETE FROM keycards WHERE owner=?1", [&owner])?;

    // Calculate the expiration time of the current entries
    let ttl_offset = current
        .get_field("Time-To-Live")
        .unwrap()
        .parse::<u16>()
        .unwrap();

    let ttl_expires = if for_caching {
        match Timestamp::new().with_offset(i64::from(ttl_offset)) {
            Some(v) => v.to_string(),
            None => {
                return Err(MensagoError::ErrProgramException(String::from(
                    "BUG: timestamp generation failure in KCResolver::update_card_in_db",
                )))
            }
        }
    } else {
        String::new()
    };

    for entry in card.entries.iter() {
        conn.execute(
            "INSERT INTO keycards(
			owner, entryindex, type, entry, textentry, hash, expires, timestamp, ttlexpires)
			VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            [
                &owner,
                &entry.get_field("Index").unwrap(),
                &entry.get_field("Type").unwrap(),
                &entry.get_full_text("").unwrap(),
                &entry.get_full_text("").unwrap(),
                &entry.get_authstr("Hash").unwrap().to_string(),
                &entry.get_field("Expires").unwrap(),
                &entry.get_field("Timestamp").unwrap(),
                &ttl_expires.to_string(),
            ],
        )?;
    }

    Ok(())
}
