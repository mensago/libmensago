use libkeycard::*;

#[derive(Debug, Clone)]
pub struct StringModel {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct NamePartModel {
    pub part_type: String,
    pub value: String,
    pub priority: String,
}

#[derive(Debug, Clone)]
pub struct NameModel {
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
    pub label: String,

    pub uid: UserID,
    pub wid: RandomID,
    pub domain: Domain,
}

#[derive(Debug, Clone)]
pub struct KeyModel {
    pub label: String,

    pub keytype: String,
    pub keyhash: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct AddressModel {
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
    pub mime_type: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FileModel {
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
