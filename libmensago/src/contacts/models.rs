use crate::base::*;
use libkeycard::*;
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
    pub table: String,
    pub id: RandomID,
    pub contact_id: RandomID,

    pub label: String,
    pub value: String,
}

impl StringModel {
    /// Creates a new empty StringModel
    pub fn new(contact_id: &RandomID, table: &str) -> StringModel {
        StringModel {
            table: String::from(table),
            id: RandomID::generate(),
            contact_id: contact_id.clone(),
            label: String::new(),
            value: String::new(),
        }
    }

    pub fn load_from_db(
        tablename: &str,
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<StringModel, MensagoError> {
        let mut stmt = conn.prepare("SELECT conid,label,value, FROM ?1 WHERE id = ?2")?;
        let (conid, label, value) = match stmt.query_row(&[tablename, &id.to_string()], |row| {
            Ok((
                row.get::<usize, String>(0).unwrap(),
                row.get::<usize, String>(1).unwrap(),
                row.get::<usize, String>(2).unwrap(),
            ))
        }) {
            Ok(v) => v,
            Err(e) => return Err(MensagoError::ErrDatabaseException(e.to_string())),
        };

        Ok(StringModel {
            id: id.clone(),
            table: String::from(tablename),
            contact_id: match RandomID::from(&conid) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conid
                    )))
                }
            },
            label,
            value,
        })
    }
}

impl DBModel for StringModel {
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "DELETE FROM ?1 WHERE id=?2",
            &[&self.table, &self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        let mut stmt = conn.prepare("SELECT conid,label,value, FROM ?1 WHERE id = ?2")?;
        let (conid, label, value) =
            match stmt.query_row(&[&self.table, &self.id.to_string()], |row| {
                Ok((
                    row.get::<usize, String>(0).unwrap(),
                    row.get::<usize, String>(1).unwrap(),
                    row.get::<usize, String>(2).unwrap(),
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
        self.label = label;
        self.value = value;

        Ok(())
    }

    fn set_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        match conn.execute(
            "INSERT OR REPLACE INTO ?1(id, conid, label, value) VALUES(?2,?3,?4,?5)",
            &[
                &self.table,
                &self.id.to_string(),
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

    /// Instantiates a NamePartModel from a model ID in the database.
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
        return Err(MensagoError::ErrUnimplemented);
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
    /// Creates a new empty NameModel
    pub fn new(contact_id: &RandomID) -> NameModel {
        NameModel {
            id: RandomID::generate(),
            contact_id: contact_id.clone(),

            formatted_name: String::new(),

            given_name: String::new(),
            family_name: String::new(),
            additional_names: Vec::new(),

            nicknames: Vec::new(),

            prefix: String::new(),
            suffixes: Vec::new(),
        }
    }

    /// `load_from_db()` instantiates a NameModel from the specified contact ID.
    pub fn load_from_db(
        id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<NameModel, MensagoError> {
        let conid: RandomID;
        let mut out: NameModel;

        {
            let mut stmt = conn.prepare(
            "SELECT conid,formattedname,givenname,familyname,prefix FROM contact_name WHERE id = ?1",
        )?;
            let (conidstr, formattedname, givenname, familyname, prefix) =
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

            conid = match RandomID::from(&conidstr) {
                Some(v) => v,
                None => {
                    return Err(MensagoError::ErrDatabaseException(format!(
                        "Bad contact ID received from database: '{}'",
                        conidstr
                    )))
                }
            };

            out = NameModel::new(&conid);
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
            "DELETE FROM contact_name WHERE id=?1",
            &[&self.id.to_string()],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(MensagoError::ErrDatabaseException(e.to_string())),
        }
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        {
            let mut stmt = conn.prepare(
            "SELECT conid,formattedname,givenname,familyname,prefix FROM contact_name WHERE id = ?1",
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
            "INSERT OR REPLACE INTO contact_name(id, conid, formattedname, givenname, familyname, 
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

    pub uid: UserID,
    pub wid: RandomID,
    pub domain: Domain,
}

/// KeyModel represents a cryptography key or keypair in the database. Note that keys are stored in
/// a user's secrets database, not regular storage.
#[derive(Debug, Clone)]
pub struct KeyModel {
    pub id: RandomID,

    pub label: String,

    pub keytype: String,
    pub keyhash: String,
    pub value: String,
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

/// PhotoModel represents a contact's photo
#[derive(Debug, Clone)]
pub struct PhotoModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub mime_type: String,
    pub data: Vec<u8>,
}

/// FileModel represents a file attached to a contact
#[derive(Debug, Clone)]
pub struct FileModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub name: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// DBContact, unlike `JSONContact`, is a model for interacting with the database
pub struct ContactModel {
    pub contact_id: RandomID,
    pub entity_type: String,

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
    pub photo: PhotoModel,

    pub languages: Vec<StringModel>,

    pub notes: String,
    pub attachments: Vec<FileModel>,
    pub custom: Vec<StringModel>,
    pub annotations: Box<Self>,
}
