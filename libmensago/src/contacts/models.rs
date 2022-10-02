use crate::base::*;
use libkeycard::*;
use rusqlite;

pub trait DBModel {
    fn load_from_db<T: DBModel>(
        contact_id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<T, MensagoError>;

    fn add_to_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn update_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError>;
}

#[derive(Debug, Clone)]
pub struct StringModel {
    pub id: RandomID,
    pub table: String,
    pub contact_id: RandomID,

    pub label: String,
    pub value: String,
}

impl StringModel {
    /// Creates a new empty StringModel
    pub fn new(contact_id: &RandomID, table: &str) -> StringModel {
        StringModel {
            id: RandomID::generate(),
            table: String::from(table),
            contact_id: contact_id.clone(),
            label: String::new(),
            value: String::new(),
        }
    }
}

impl DBModel for StringModel {
    fn load_from_db<T: DBModel>(
        contact_id: &RandomID,
        conn: &mut rusqlite::Connection,
    ) -> Result<T, MensagoError> {
        // TODO: Implement StringModel::load_from_db
        Err(MensagoError::ErrUnimplemented)
    }

    fn add_to_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        // TODO: Implement StringModel::add_to_db
        Err(MensagoError::ErrUnimplemented)
    }

    fn refresh_from_db(&mut self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        // TODO: Implement StringModel::refresh_from_db
        Err(MensagoError::ErrUnimplemented)
    }

    fn update_in_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        // TODO: Implement StringModel::update_in_db
        Err(MensagoError::ErrUnimplemented)
    }

    fn delete_from_db(&self, conn: &mut rusqlite::Connection) -> Result<(), MensagoError> {
        // TODO: Implement StringModel::delete_from_db
        Err(MensagoError::ErrUnimplemented)
    }
}

#[derive(Debug, Clone)]
pub struct NamePartModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub part_type: String,
    pub value: String,
    pub priority: String,
}

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

#[derive(Debug, Clone)]
pub struct MensagoModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub label: String,

    pub uid: UserID,
    pub wid: RandomID,
    pub domain: Domain,
}

#[derive(Debug, Clone)]
pub struct KeyModel {
    pub id: RandomID,

    pub label: String,

    pub keytype: String,
    pub keyhash: String,
    pub value: String,
}

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

#[derive(Debug, Clone)]
pub struct PhotoModel {
    pub id: RandomID,
    pub contact_id: RandomID,

    pub mime_type: String,
    pub data: Vec<u8>,
}

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
