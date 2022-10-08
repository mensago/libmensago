use crate::{base::*, types::*, EntityType, SeparatedStrList};
use eznacl::*;
use libkeycard::*;
use mime::Mime;
use rusqlite;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

pub trait DBModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
}

/// StringModel is just a base class to represent key-value pairs in the database.
#[derive(Debug, Clone)]
pub struct StringModel {
    pub id: RandomID,
    pub itemtype: String,
    pub contact_id: RandomID,

    pub label: String,
    pub value: String,
}

impl StringModel {
    /// Creates a new empty StringModel
    pub fn new(contact_id: &RandomID, itemtype: &str) -> StringModel {
        StringModel {
            id: RandomID::generate(),
            itemtype: String::from(itemtype),
            contact_id: contact_id.clone(),
            label: String::new(),
            value: String::new(),
        }
    }

    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<StringModel, MensagoError> {
        let mut stmt =
            conn.prepare("SELECT conid,itemtype,label,value FROM contact_keyvalue WHERE id = ?1")?;
        let (conidstr, itemtype, label, value) = match stmt.query_row(&[&id.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, String>(2).unwrap(),
                row.get::<usize, String>(3).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        Ok(StringModel {
            id: id.clone(),
            itemtype,
            contact_id: match RandomID::from(&conidstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conidstr
                    )))
                }
            },
            label,
            value,
        })
    }

    /// Returns a list of all StringModels of a particular type that belong to a specific contact.
    pub fn load_all(
        conid: &RandomID,
        itemtype: &str,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<StringModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();

        let mut stmt = match conn
            .prepare("SELECT id FROM contact_keyvalue WHERE conid = ?1 AND itemtype = ?2")
        {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut rows = match stmt.query([&conid.as_string(), itemtype]) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        while option_row.is_some() {
            let row = option_row.unwrap();
            let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad string model ID {} in contact_keyvalue",
                        &row.get::<usize, String>(0).unwrap()
                    )))
                }
            };
            ids.push(partid);

            option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        }
        drop(rows);
        drop(stmt);

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(StringModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }
}

impl DBModel for StringModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_keyvalue WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt =
            conn.prepare("SELECT conid,itemtype,label,value FROM contact_keyvalue WHERE id = ?1")?;
        let (conid, itemtype, label, value) = match stmt.query_row(&[&self.id.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, String>(2).unwrap(),
                row.get::<usize, String>(3).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        self.contact_id = match RandomID::from(&conid) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact ID received from database: '{}'",
                    conid
                )))
            }
        };
        self.itemtype = itemtype;
        self.label = label;
        self.value = value;

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_keyvalue(id,itemtype,conid,label,value) 
            VALUES(?1,?2,?3,?4,?5)",
            &[
                &self.id.to_string(),
                &self.itemtype.to_string(),
                &self.contact_id.to_string(),
                &self.label,
                &self.value,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum NamePartType {
    None,
    Additional,
    Nickname,
    Suffix,
}

impl fmt::Display for NamePartType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NamePartType::None => write!(f, "none"),
            NamePartType::Additional => write!(f, "additional"),
            NamePartType::Nickname => write!(f, "nickname"),
            NamePartType::Suffix => write!(f, "suffix"),
        }
    }
}

impl FromStr for NamePartType {
    type Err = ();

    fn from_str(input: &str) -> Result<NamePartType, Self::Err> {
        match input.to_lowercase().as_str() {
            "none" => Ok(NamePartType::None),
            "additional" => Ok(NamePartType::Additional),
            "nickname" => Ok(NamePartType::Nickname),
            "suffix" => Ok(NamePartType::Suffix),
            _ => Err(()),
        }
    }
}

impl std::convert::TryFrom<&str> for NamePartType {
    type Error = MensagoError;
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        match input.to_lowercase().as_str() {
            "none" => Ok(NamePartType::None),
            "additional" => Ok(NamePartType::Additional),
            "nickname" => Ok(NamePartType::Nickname),
            "suffix" => Ok(NamePartType::Suffix),
            _ => Err(MensagoError::ErrBadValue),
        }
    }
}

/// NamePartModel is a database representation of a part of a name which is not one of the base
/// name components -- middle name(s), suffixes, or nicknames.
#[derive(Debug, Clone)]
pub struct NamePartModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub part_type: NamePartType,
    pub value: String,
    pub priority: usize,
}

impl NamePartModel {
    /// Creates a new empty NamePartModel
    pub fn new(contact_id: &RandomID) -> NamePartModel {
        NamePartModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),
            part_type: NamePartType::None,
            value: String::new(),
            priority: 0,
        }
    }

    /// Instantiates a NamePartModel from a model ID in the database. Note that this call is
    /// different from `NameModel::load_from_db` in that the model's ID is required, not the contact
    /// ID. This is because a contact has only one name structure, but the name structure itself
    /// has components which can be in multiples, such as nicknames.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<NamePartModel, MensagoError> {
        let mut stmt = conn
            .prepare("SELECT conid,parttype,value,priority FROM contact_nameparts WHERE id = ?1")?;
        let (conid, parttype, value, priority) = match stmt.query_row(&[&id.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, String>(2).unwrap(),
                row.get::<usize, String>(3).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        Ok(NamePartModel {
            id: id.clone(),
            contact_id: match RandomID::from(&conid) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conid
                    )))
                }
            },
            part_type: NamePartType::try_from(parttype.as_str())?,
            value,
            priority: match priority.parse::<usize>() {
                Ok(v) => v,
                Err(_) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad priority received from database: '{}'",
                        priority
                    )))
                }
            },
        })
    }

    /// Returns a list of all NamePartModels in the database of a particular type that belong to a
    /// specific contact.
    pub fn load_all(
        conid: &RandomID,
        parttype: NamePartType,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<NamePartModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();
        {
            let mut stmt = match conn
                .prepare("SELECT id FROM contact_nameparts WHERE conid = ?1 and parttype = ?2")
            {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut rows = match stmt.query([&conid.as_string(), parttype.to_string().as_str()]) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            while option_row.is_some() {
                let row = option_row.unwrap();
                let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                    Some(v) => v,
                    None => {
                        return Err(MensagoError::ErrDatabaseException(format!(
                            "Bad name part ID {} in contact_nameparts",
                            &row.get::<usize, String>(0).unwrap()
                        )))
                    }
                };
                ids.push(partid);

                option_row = match rows.next() {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };
            }
        }

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(NamePartModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }

    pub fn set_all(
        models: &Vec<NamePartModel>,
        conn: &mut rusqlite::Connection,
    ) -> Result<(), MensagoError> {
        for model in models.iter() {
            model.set_in_db(conn)?;
        }
        Ok(())
    }
}

impl DBModel for NamePartModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_nameparts WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt = conn
            .prepare("SELECT conid,parttype,value,priority FROM contact_nameparts WHERE id = ?1")?;
        let (conid, parttype, value, priority) =
            match stmt.query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

        self.contact_id = match RandomID::from(&conid) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact ID received from database: '{}'",
                    conid
                )))
            }
        };
        self.part_type = NamePartType::try_from(parttype.as_str())?;
        self.value = value;
        self.priority = match priority.parse::<usize>() {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad priority received from database: '{}'",
                    priority
                )))
            }
        };

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_nameparts(id, conid, parttype, value, priority) VALUES(?1,?2,?3,?4,?5)",
            &[
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.part_type.to_string(),
                &self.value.to_string(),
                &self.priority.to_string(),
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

/// NameModel is the database representation of a contact's name and all the miscellaneous
/// components that go with it.
#[derive(Debug, Clone)]
pub struct NameModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub formatted_name: String,

    pub given_name: String,
    pub family_name: String,
    pub additional_names: Vec<NamePartModel>,

    pub nicknames: Vec<NamePartModel>,

    pub prefix: String,
    pub suffixes: Vec<NamePartModel>,
}

impl NameModel {
    /// Creates a new NameModel. The spec requires each contact to at least have something in the
    /// GivenName field. This call will panic if given an empty string or one containing only
    /// whitespace.
    pub fn new(contact_id: &RandomID, givenname: &str) -> NameModel {
        let gn = String::from(givenname.trim());
        if gn.len() < 1 {
            panic!();
        }

        NameModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),

            formatted_name: String::new(),

            given_name: gn,
            family_name: String::new(),
            additional_names: Vec::new(),

            nicknames: Vec::new(),

            prefix: String::new(),
            suffixes: Vec::new(),
        }
    }

    /// `load_from_db()` instantiates a NameModel from the specified contact ID.
    pub fn load_from_db(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<NameModel, MensagoError> {
        let mut out: NameModel;

        {
            let mut stmt = conn.prepare(
            "SELECT id,formatted_name,given_name,family_name,prefix FROM contact_names WHERE conid = ?1",
        )?;
            let (idstr, formattedname, givenname, familyname, prefix) =
                match stmt.query_row(&[&conid.to_string()], |row| {
                    Ok((
                        row.get::<usize, String>(0).unwrap(),
                        row.get::<usize, String>(1).unwrap(),
                        row.get::<usize, String>(2).unwrap(),
                        row.get::<usize, String>(3).unwrap(),
                        row.get::<usize, String>(4).unwrap(),
                    ))
                }) {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };

            let id = match RandomID::from(&idstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact name ID received from database: '{}'",
                        idstr
                    )))
                }
            };

            out = NameModel::new(&conid, &givenname);
            out.id = id;
            out.formatted_name = formattedname;
            out.given_name = givenname;
            out.family_name = familyname;
            out.prefix = prefix;
        }

        out.additional_names = NamePartModel::load_all(&conid, NamePartType::Additional, conn)?;
        out.nicknames = NamePartModel::load_all(&conid, NamePartType::Nickname, conn)?;
        out.suffixes = NamePartModel::load_all(&conid, NamePartType::Suffix, conn)?;

        Ok(out)
    }
}

impl DBModel for NameModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_names WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        {
            let mut stmt = conn.prepare(
            "SELECT conid,formatted_name,given_name,family_name,prefix FROM contact_names WHERE id = ?1",
        )?;
            let (conidstr, formattedname, givenname, familyname, prefix) =
                match stmt.query_row(&[&self.id.to_string()], |row| {
                    Ok((
                        row.get::<usize, String>(0).unwrap(),
                        row.get::<usize, String>(1).unwrap(),
                        row.get::<usize, String>(2).unwrap(),
                        row.get::<usize, String>(3).unwrap(),
                        row.get::<usize, String>(4).unwrap(),
                    ))
                }) {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };

            let conid = match RandomID::from(&conidstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conidstr
                    )))
                }
            };

            self.contact_id = conid;
            self.formatted_name = formattedname;
            self.given_name = givenname;
            self.family_name = familyname;
            self.prefix = prefix;
        }

        self.additional_names =
            NamePartModel::load_all(&self.contact_id, NamePartType::Additional, conn)?;
        self.nicknames = NamePartModel::load_all(&self.contact_id, NamePartType::Nickname, conn)?;
        self.suffixes = NamePartModel::load_all(&self.contact_id, NamePartType::Suffix, conn)?;

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_names(id, conid, formatted_name, given_name, family_name, 
            prefix) VALUES(?1,?2,?3,?4,?5,?6)",
            &[
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.formatted_name.to_string(),
                &self.given_name.to_string(),
                &self.family_name.to_string(),
                &self.prefix.to_string(),
            ],
        ) {
            Ok(_) => (),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }

        NamePartModel::set_all(&self.additional_names, conn)?;
        NamePartModel::set_all(&self.nicknames, conn)?;
        NamePartModel::set_all(&self.suffixes, conn)
    }
}

/// MensagoModel represents a Mensago address or a workspace address in the database.
#[derive(Debug, Clone)]
pub struct MensagoModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub label: String,

    pub uid: Option<UserID>,
    pub wid: RandomID,
    pub domain: Domain,
}

impl MensagoModel {
    /// Creates a new empty MensagoModel
    pub fn new(
        contact_id: &RandomID,
        label: &str,
        uid: Option<&UserID>,
        wid: &RandomID,
        domain: &Domain,
    ) -> MensagoModel {
        MensagoModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),
            label: String::from(label),
            uid: match uid {
                Some(v) => Some(v.clone()),
                None => None,
            },
            wid: wid.clone(),
            domain: domain.clone(),
        }
    }

    /// Instantiates a MensagoModel from a model ID in the database. If you would like to load all
    /// of a contact's Mensago addresses, look at `load_all()` in combination with this call.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<MensagoModel, MensagoError> {
        let mut stmt =
            conn.prepare("SELECT conid,label,uid,wid,domain FROM contact_mensago WHERE id = ?1")?;
        let (conidstr, label, uidstr, widstr, domstr) =
            match stmt.query_row(&[&id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

        Ok(MensagoModel {
            id: id.clone(),
            contact_id: RandomID::try_from(conidstr.as_str())?,
            label,
            uid: Some(UserID::try_from(uidstr.as_str())?),
            wid: RandomID::try_from(widstr.as_str())?,
            domain: Domain::try_from(domstr.as_str())?,
        })
    }

    /// Returns a list of all MensagoModels in the database of a particular type that belong to a
    /// specific contact.
    pub fn load_all(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<MensagoModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();
        {
            let mut stmt = match conn.prepare("SELECT id FROM contact_mensago WHERE conid = ?1") {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut rows = match stmt.query([&conid.as_string()]) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            while option_row.is_some() {
                let row = option_row.unwrap();
                let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                    Some(v) => v,
                    None => {
                        return Err(MensagoError::ErrDatabaseException(format!(
                            "Bad Mensago address ID {} in contact_mensago",
                            &row.get::<usize, String>(0).unwrap()
                        )))
                    }
                };
                ids.push(partid);

                option_row = match rows.next() {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };
            }
        }

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(MensagoModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }

    pub fn set_all(
        models: &Vec<MensagoModel>,
        conn: &mut rusqlite::Connection,
    ) -> Result<(), MensagoError> {
        for model in models.iter() {
            model.set_in_db(conn)?;
        }
        Ok(())
    }
}

impl DBModel for MensagoModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_mensago WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt =
            conn.prepare("SELECT conid,label,uid,wid,domain FROM contact_mensago WHERE id = ?1")?;
        let (conidstr, labelstr, uidstr, widstr, domstr) =
            match stmt.query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        self.label = labelstr;

        self.contact_id = match RandomID::from(&conidstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact ID received from database: '{}'",
                    conidstr
                )))
            }
        };
        self.uid = match UserID::from(&uidstr) {
            Some(v) => Some(v.clone()),
            None => None,
        };
        self.wid = match RandomID::from(&widstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad workspace ID received from database: '{}'",
                    domstr
                )))
            }
        };
        self.domain = match Domain::from(&domstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad domain received from database: '{}'",
                    domstr
                )))
            }
        };

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let uidstr = match &self.uid {
            Some(v) => v.to_string(),
            None => String::new(),
        };

        match conn.execute(
            "INSERT OR REPLACE INTO contact_mensago(id, conid, label, uid, wid, domain) VALUES(?1,?2,?3,?4,?5,?6)",
            &[
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.label,
                &uidstr,
                &self.wid.to_string(),
                &self.domain.to_string(),
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

/// KeyModel represents a cryptography key or keypair in the database. Note that keys are stored in
/// a user's secrets database, not regular storage.
#[derive(Debug, Clone)]
pub struct KeyModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub label: String,
    pub category: KeyCategory,
    pub key: CryptoString,
    pub timestamp: Timestamp,
}

impl KeyModel {
    /// Creates a new empty KeyModel.
    pub fn new(
        contact_id: &RandomID,
        label: &str,
        category: KeyCategory,
        key: &CryptoString,
    ) -> KeyModel {
        KeyModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),
            label: String::from(label),
            category,
            key: key.clone(),
            timestamp: Timestamp::new(),
        }
    }

    /// Instantiates a KeyModel from a model ID in the database. If you would like to load all
    /// of a contact's keys, look at `load_all()`.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<KeyModel, MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT conid,label,category,value,timestamp FROM contact_keys WHERE id = ?1",
        )?;
        let (conidstr, label, catstr, valstr, timestr) =
            match stmt.query_row(&[&id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

        Ok(KeyModel {
            id: id.clone(),
            contact_id: RandomID::try_from(conidstr.as_str())?,
            label,
            category: KeyCategory::try_from(catstr.as_str())?,
            key: CryptoString::try_from(valstr.as_str())?,
            timestamp: Timestamp::try_from(timestr.as_str())?,
        })
    }

    /// Returns a list of all KeyModels in the database of a particular type that belong to a
    /// specific contact.
    pub fn load_all(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<KeyModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();
        {
            let mut stmt = match conn.prepare("SELECT id FROM contact_keys WHERE conid = ?1") {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut rows = match stmt.query([&conid.as_string()]) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            while option_row.is_some() {
                let row = option_row.unwrap();
                let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                    Some(v) => v,
                    None => {
                        return Err(MensagoError::ErrDatabaseException(format!(
                            "Bad key model ID {} in contact_keys",
                            &row.get::<usize, String>(0).unwrap()
                        )))
                    }
                };
                ids.push(partid);

                option_row = match rows.next() {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };
            }
        }

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(KeyModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }

    pub fn set_all(
        models: &Vec<MensagoModel>,
        conn: &mut rusqlite::Connection,
    ) -> Result<(), MensagoError> {
        for model in models.iter() {
            model.set_in_db(conn)?;
        }
        Ok(())
    }
}

impl DBModel for KeyModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_keys WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT conid,label,category,value,timestamp FROM contact_keys WHERE id = ?1",
        )?;
        let (conidstr, labelstr, catstr, keystr, timestr) =
            match stmt.query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        self.label = labelstr;

        self.contact_id = match RandomID::from(&conidstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact ID received from database: '{}'",
                    conidstr
                )))
            }
        };
        self.category = match KeyCategory::try_from(catstr.as_str()) {
            Ok(v) => v,
            Err(_) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad key category received from database: '{}'",
                    catstr
                )))
            }
        };
        self.key = match CryptoString::from(&keystr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact key received from database: '{}'",
                    keystr
                )))
            }
        };
        self.timestamp = match Timestamp::from_str(&timestr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad timestamp received from database: '{}'",
                    timestr
                )))
            }
        };

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_keys(id, conid, label, category, value, timestamp) 
            VALUES(?1,?2,?3,?4,?5,?6)",
            &[
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.label,
                &self.category.to_string(),
                &self.key.to_string(),
                &self.timestamp.to_string(),
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

/// AddressModel represents a contact's street address
#[derive(Debug, Clone)]
pub struct AddressModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub label: String,

    pub street: String,
    pub extended: String,
    pub locality: String,
    pub region: String,
    pub postalcode: String,
    pub country: String,

    pub preferred: bool,
}

impl AddressModel {
    /// Creates a new empty KeyModel.
    pub fn new(contact_id: &RandomID, label: &str) -> AddressModel {
        AddressModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),
            label: String::from(label),
            street: String::new(),
            extended: String::new(),
            locality: String::new(),
            region: String::new(),
            postalcode: String::new(),
            country: String::new(),

            preferred: false,
        }
    }

    /// Instantiates a AddressModel from a model ID in the database. If you would like to load all
    /// of a contact's keys, look at `load_all()`.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<AddressModel, MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT conid,label,street,extended,locality,region,postalcode,country,preferred 
            FROM contact_address WHERE id = ?1",
        )?;
        let (conidstr, label, street, extended, locality, region, postalcode, country, preferred) =
            match stmt.query_row(&[&id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                    row.get::<usize, String>(5).unwrap(),
                    row.get::<usize, String>(6).unwrap(),
                    row.get::<usize, String>(7).unwrap(),
                    row.get::<usize, bool>(8).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

        Ok(AddressModel {
            id: id.clone(),
            contact_id: RandomID::try_from(conidstr.as_str())?,
            label,
            street,
            extended,
            locality,
            region,
            postalcode,
            country,
            preferred,
        })
    }

    /// Returns a list of all AddressModels in the database of a particular type that belong to a
    /// specific contact.
    pub fn load_all(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<AddressModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();
        {
            let mut stmt = match conn.prepare("SELECT id FROM contact_address WHERE conid = ?1") {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut rows = match stmt.query([&conid.as_string()]) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let mut option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            while option_row.is_some() {
                let row = option_row.unwrap();
                let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                    Some(v) => v,
                    None => {
                        return Err(MensagoError::ErrDatabaseException(format!(
                            "Bad address model ID {} in contact_address",
                            &row.get::<usize, String>(0).unwrap()
                        )))
                    }
                };
                ids.push(partid);

                option_row = match rows.next() {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };
            }
        }

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(AddressModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }

    pub fn set_all(
        models: &Vec<MensagoModel>,
        conn: &mut rusqlite::Connection,
    ) -> Result<(), MensagoError> {
        for model in models.iter() {
            model.set_in_db(conn)?;
        }
        Ok(())
    }
}

impl DBModel for AddressModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_address WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT conid,label,street,extended,locality,region,postalcode,country,preferred 
            FROM contact_address WHERE id = ?1",
        )?;
        let (conidstr, label, street, extended, locality, region, postalcode, country, preferred) =
            match stmt.query_row(&[&self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, String>(3).unwrap(),
                    row.get::<usize, String>(4).unwrap(),
                    row.get::<usize, String>(5).unwrap(),
                    row.get::<usize, String>(6).unwrap(),
                    row.get::<usize, String>(7).unwrap(),
                    row.get::<usize, bool>(8).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        self.label = label;
        self.street = street;
        self.extended = extended;
        self.locality = locality;
        self.region = region;
        self.postalcode = postalcode;
        self.country = country;
        self.preferred = preferred;

        self.contact_id = match RandomID::from(&conidstr) {
            Some(v) => v,
            None => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad contact ID received from database: '{}'",
                    conidstr
                )))
            }
        };

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_address(id,conid,label,street,extended,locality,region,
            postalcode,country,preferred) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            rusqlite::params![
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.label,
                &self.street,
                &self.extended,
                &self.locality,
                &self.region,
                &self.postalcode,
                &self.country,
                &self.preferred,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

/// PhotoModel represents a contact's photo
#[derive(Debug, Clone)]
pub struct PhotoModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub mime_type: Mime,
    pub data: Vec<u8>,
}

impl PhotoModel {
    /// Creates a new empty PhotoModel
    pub fn new(contact_id: &RandomID, mimetype: &Mime, imgdata: &Vec<u8>) -> PhotoModel {
        PhotoModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),
            mime_type: mimetype.clone(),
            data: imgdata.clone(),
        }
    }

    /// `load_from_db()` instantiates a PhotoModel from the specified contact ID.
    pub fn load_from_db(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<PhotoModel, MensagoError> {
        let mut out: PhotoModel;

        {
            let mut stmt =
                conn.prepare("SELECT id,mime,data FROM contact_photo WHERE conid = ?1")?;
            let (idstr, mimestr, imgdata) = match stmt.query_row(&[&conid.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, Vec<u8>>(2).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let id = match RandomID::from(&idstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad photo ID received from database: '{}'",
                        idstr
                    )))
                }
            };
            let imgtype = match Mime::from_str(&mimestr) {
                Ok(v) => v,
                Err(_) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad photo MIME type received from database: '{}'",
                        mimestr
                    )))
                }
            };

            out = PhotoModel::new(&conid, &imgtype, &imgdata);
            out.id = id;
        }
        Ok(out)
    }
}

impl DBModel for PhotoModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_photo WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        {
            let mut stmt =
                conn.prepare("SELECT conid,mime,data FROM contact_photo WHERE id = ?1")?;
            let (conidstr, mimestr, imgdata) =
                match stmt.query_row(&[&self.id.to_string()], |row| {
                    Ok((
                        row.get::<usize, String>(0).unwrap(),
                        row.get::<usize, String>(1).unwrap(),
                        row.get::<usize, Vec<u8>>(2).unwrap(),
                    ))
                }) {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };

            let conid = match RandomID::from(&conidstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conidstr
                    )))
                }
            };
            let imgtype = match Mime::from_str(&mimestr) {
                Ok(v) => v,
                Err(_) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad photo MIME type received from database: '{}'",
                        mimestr
                    )))
                }
            };

            self.contact_id = conid;
            self.mime_type = imgtype;
            self.data = imgdata;
        }
        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_photo(id,conid,mime,data) VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.mime_type.to_string(),
                &self.data,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

/// FileModel represents a file attached to a contact. This holds the raw data of the file in
/// memory while it exists. It would be wise to restrict the size of the files stored into a
/// contact. Just sayin'. 🙃
#[derive(Debug, Clone)]
pub struct FileModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub name: String,
    pub mime_type: Mime,
    pub data: Vec<u8>,
}

impl FileModel {
    /// Creates a new empty FileModel
    pub fn new(contact_id: &RandomID, name: &str, mimetype: &Mime, imgdata: &Vec<u8>) -> FileModel {
        FileModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),

            name: String::from(name),
            mime_type: mimetype.clone(),
            data: imgdata.clone(),
        }
    }

    /// `load_from_db()` instantiates a FileModel from the specified file ID.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<FileModel, MensagoError> {
        let mut out: FileModel;

        {
            let mut stmt =
                conn.prepare("SELECT conid,name,mime,data FROM contact_files WHERE id = ?1")?;
            let (idstr, name, mimestr, imgdata) = match stmt.query_row(&[&id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
                    row.get::<usize, Vec<u8>>(3).unwrap(),
                ))
            }) {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };

            let id = match RandomID::from(&idstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad file ID received from database: '{}'",
                        idstr
                    )))
                }
            };
            let imgtype = match Mime::from_str(&mimestr) {
                Ok(v) => v,
                Err(_) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad file MIME type received from database: '{}'",
                        mimestr
                    )))
                }
            };

            out = FileModel::new(&id, &name, &imgtype, &imgdata);
            out.id = id;
        }
        Ok(out)
    }

    /// Returns a list of all FileModels that belong to a specific contact.
    pub fn load_all(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<Vec<FileModel>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();

        let mut stmt = match conn.prepare("SELECT id FROM contact_files WHERE conid = ?1") {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut rows = match stmt.query([&conid.as_string()]) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        let mut option_row = match rows.next() {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        while option_row.is_some() {
            let row = option_row.unwrap();
            let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad file model ID {} in contact_files",
                        &row.get::<usize, String>(0).unwrap()
                    )))
                }
            };
            ids.push(partid);

            option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        }
        drop(rows);
        drop(stmt);

        let mut out = Vec::new();
        for id in ids.iter() {
            out.push(FileModel::load_from_db(&id, conn)?);
        }

        Ok(out)
    }
}

impl DBModel for FileModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM contact_files WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        {
            let mut stmt =
                conn.prepare("SELECT conid,name,mime,data FROM contact_files WHERE id = ?1")?;
            let (conidstr, name, mimestr, imgdata) =
                match stmt.query_row(&[&self.id.to_string()], |row| {
                    Ok((
                        row.get::<usize, String>(0).unwrap(),
                        row.get::<usize, String>(1).unwrap(),
                        row.get::<usize, String>(2).unwrap(),
                        row.get::<usize, Vec<u8>>(3).unwrap(),
                    ))
                }) {
                    Ok(v) => v,
                    Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
                };

            let conid = match RandomID::from(&conidstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conidstr
                    )))
                }
            };
            let imgtype = match Mime::from_str(&mimestr) {
                Ok(v) => v,
                Err(_) => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad file MIME type received from database: '{}'",
                        mimestr
                    )))
                }
            };

            self.contact_id = conid;
            self.name = name;
            self.mime_type = imgtype;
            self.data = imgdata;
        }
        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO contact_files(id,conid,name,mime,data) VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![
                &self.id.to_string(),
                &self.contact_id.to_string(),
                &self.name,
                &self.mime_type.to_string(),
                &self.data,
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }
}

/// DBContact, unlike `JSONContact`, is a model for interacting with the database
pub struct ContactModel {
    pub id: RandomID,
    pub entity_type: EntityType,

    pub group: String,

    pub name: NameModel,
    pub gender: String,
    pub bio: String,

    pub social: Vec<StringModel>,
    pub mensago: Vec<MensagoModel>,

    pub keys: Vec<KeyModel>,

    pub messaging: Vec<StringModel>,

    pub addresses: Vec<AddressModel>,
    pub phone: Vec<StringModel>,

    pub anniversary: String,
    pub birthday: String,

    pub email: Vec<StringModel>,

    pub organization: String,
    pub orgunits: Vec<String>,
    pub title: String,
    pub categories: Vec<String>,

    pub websites: Vec<StringModel>,
    pub photo: Option<PhotoModel>,

    pub languages: Vec<String>,

    pub notes: String,
    pub attachments: Vec<FileModel>,
    pub custom: Vec<StringModel>,
    pub annotations: Option<Box<Self>>,
}

impl ContactModel {
    /// Creates a new empty ContactModel, which defaults to representing an individual
    pub fn new(givenname: &str) -> ContactModel {
        let conid = RandomID::generate();
        ContactModel {
            id: conid.clone(),
            entity_type: EntityType::Individual,
            group: String::new(),
            name: NameModel::new(&conid, givenname),
            gender: String::new(),
            bio: String::new(),
            social: Vec::new(),
            mensago: Vec::new(),
            keys: Vec::new(),
            messaging: Vec::new(),
            addresses: Vec::new(),
            phone: Vec::new(),
            anniversary: String::new(),
            birthday: String::new(),
            email: Vec::new(),
            organization: String::new(),
            orgunits: Vec::new(),
            title: String::new(),
            categories: Vec::new(),
            websites: Vec::new(),
            photo: None,
            languages: Vec::new(),
            notes: String::new(),
            attachments: Vec::new(),
            custom: Vec::new(),
            annotations: None,
        }
    }

    /// `load_from_db()` instantiates a ContactModel from the specified contact ID.
    pub fn load_from_db(
        conid: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<ContactModel, MensagoError> {
        let mut stmt = conn.prepare(
            "SELECT entitytype,group,gender,bio,anniversary,birthday,organization,orgunits,
            title,categories,languages,notes FROM contacts WHERE conid = ?1 AND annotation=false",
        )?;
        let (
            entitytypestr,
            group,
            gender,
            bio,
            anniversary,
            birthday,
            organization,
            orgunitstr,
            title,
            categorystr,
            languagestr,
            notes,
        ) = match stmt.query_row(&[&conid.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, String>(2).unwrap(),
                row.get::<usize, String>(3).unwrap(),
                row.get::<usize, String>(4).unwrap(),
                row.get::<usize, String>(5).unwrap(),
                row.get::<usize, String>(6).unwrap(),
                row.get::<usize, String>(7).unwrap(),
                row.get::<usize, String>(8).unwrap(),
                row.get::<usize, String>(9).unwrap(),
                row.get::<usize, String>(10).unwrap(),
                row.get::<usize, String>(11).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        // Drop so we can use conn again later on
        drop(stmt);

        let entity_type = match EntityType::try_from(entitytypestr.as_str()) {
            Ok(v) => v,
            Err(v) => {
                return Err(MensagoError::ErrDatabaseException(format!(
                    "Bad entity type received from database: '{}'",
                    v
                )))
            }
        };
        let unitlist = SeparatedStrList::from(&orgunitstr, ",");
        let catlist = SeparatedStrList::from(&categorystr, ",");
        let langlist = SeparatedStrList::from(&languagestr, ",");

        let photo = match PhotoModel::load_from_db(conid, conn) {
            Ok(v) => Some(v),
            Err(_) => None,
        };

        // All the values simple types have been loaded, so now we just load the ones which
        // have a dedicated type model

        Ok(ContactModel {
            id: conid.clone(),
            entity_type,
            group,
            name: NameModel::load_from_db(conid, conn)?,
            gender,
            bio,
            social: StringModel::load_all(conid, "social", conn)?,
            mensago: MensagoModel::load_all(conid, conn)?,
            keys: KeyModel::load_all(conid, conn)?,
            messaging: StringModel::load_all(conid, "messaging", conn)?,
            addresses: AddressModel::load_all(conid, conn)?,
            phone: StringModel::load_all(conid, "phone", conn)?,
            anniversary,
            birthday,
            email: StringModel::load_all(conid, "email", conn)?,
            organization,
            orgunits: unitlist.items,
            title,
            categories: catlist.items,
            websites: StringModel::load_all(conid, "website", conn)?,
            photo,
            languages: langlist.items,
            notes,
            attachments: FileModel::load_all(conid, conn)?,
            custom: StringModel::load_all(conid, "custom", conn)?,
            annotations: None,
        })
    }

    /// Returns the IDs of all contacts in the database.
    ///
    /// Because file attachments can make ContactModels very large and a user may have thousands of
    /// contacts, this method and `get_names()` are the two ways of getting information
    /// about all of the user's contacts at once and dealing with them iteratively. Generally
    /// speaking, you probably want `get_names()`.
    pub fn get_ids(conn: &mut rusqlite::Connection) -> Result<Vec<RandomID>, MensagoError> {
        let mut ids = Vec::<RandomID>::new();

        let mut stmt = match conn.prepare("SELECT id FROM contacts") {
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

        while option_row.is_some() {
            let row = option_row.unwrap();
            let partid = match RandomID::from(&row.get::<usize, String>(0).unwrap()) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact model ID {} in contacts",
                        &row.get::<usize, String>(0).unwrap()
                    )))
                }
            };
            ids.push(partid);

            option_row = match rows.next() {
                Ok(v) => v,
                Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
            };
        }

        Ok(ids)
    }

    /// This convenience method returns a list of NameModels representing all the user's contacts.
    ///
    /// Because file attachments can make ContactModels very large and a user may have thousands of
    /// contacts, this method and `get_ids()` are the two ways of getting information about all of
    /// the user's contacts at once and dealing with them iteratively.
    #[inline]
    pub fn get_names(conn: &mut rusqlite::Connection) -> Result<Vec<NameModel>, MensagoError> {
        let mut out = Vec::<NameModel>::new();

        for id in ContactModel::get_ids(conn)? {
            out.push(NameModel::load_from_db(&id, conn)?)
        }
        Ok(out)
    }

    // TODO: Implement DBModel trait for ContactModel
}
