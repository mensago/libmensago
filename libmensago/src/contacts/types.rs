use libkeycard::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringField {
    #[serde(rename = "Label")]
    pub label: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameField {
    #[serde(rename = "FormattedName")]
    pub formatted_name: String,

    #[serde(rename = "GivenName")]
    pub given_name: String,
    #[serde(rename = "FamilyName")]
    pub family_name: String,
    #[serde(rename = "AdditionalNames")]
    pub additional_names: Vec<String>,

    #[serde(rename = "Nicknames")]
    pub nicknames: Vec<String>,

    #[serde(rename = "Prefix")]
    pub prefix: String,
    #[serde(rename = "Suffixes")]
    pub suffixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MensagoField {
    #[serde(rename = "Label")]
    pub label: String,

    #[serde(rename = "UserID")]
    pub uid: UserID,
    #[serde(rename = "Workspace")]
    pub wid: RandomID,
    #[serde(rename = "Domain")]
    pub domain: Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyField {
    #[serde(rename = "Label")]
    pub label: String,

    #[serde(rename = "KeyType")]
    pub keytype: String,
    #[serde(rename = "KeyHash")]
    pub keyhash: String,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailingAddr {
    #[serde(rename = "Label")]
    pub label: String,

    #[serde(rename = "StreetAddress")]
    pub street: String,
    #[serde(rename = "ExtendedAddress")]
    pub extended: String,
    #[serde(rename = "Locality")]
    pub locality: String,
    #[serde(rename = "Region")]
    pub region: String,
    #[serde(rename = "PostalCode")]
    pub postalcode: String,
    #[serde(rename = "Country")]
    pub country: String,

    #[serde(rename = "Preferred")]
    pub preferred: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhotoField {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "EntityType")]
    pub entity_type: String,
    #[serde(rename = "Source")]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileField {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Mime")]
    pub mime: String,
    #[serde(rename = "Data")]
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "EntityType")]
    pub entity_type: String,
    #[serde(rename = "Source")]
    pub source: String,

    #[serde(rename = "Name")]
    pub name: NameField,

    #[serde(rename = "Gender")]
    pub gender: String,
    #[serde(rename = "Bio")]
    pub bio: String,

    #[serde(rename = "Social")]
    pub social: Vec<StringField>,

    #[serde(rename = "Mensago")]
    pub mensago: Vec<MensagoField>,

    #[serde(rename = "Keys")]
    pub keys: Vec<KeyField>,

    #[serde(rename = "Messaging")]
    pub messaging: Vec<StringField>,

    #[serde(rename = "MailingAddresses")]
    pub addresses: Vec<MailingAddr>,

    #[serde(rename = "Phone")]
    pub phone: Vec<StringField>,

    #[serde(rename = "Anniversary")]
    pub anniversary: String,
    #[serde(rename = "Birthday")]
    pub birthday: String,

    #[serde(rename = "Email")]
    pub email: Vec<StringField>,

    #[serde(rename = "Organization")]
    pub organization: String,
    #[serde(rename = "OrgUnits")]
    pub orgunits: Vec<String>,
    #[serde(rename = "Title")]
    pub title: String,

    #[serde(rename = "Categories")]
    pub categories: Vec<String>,

    #[serde(rename = "Websites")]
    pub websites: Vec<StringField>,

    #[serde(rename = "Photo")]
    photo: PhotoField,

    #[serde(rename = "Languages")]
    pub languages: Vec<StringField>,

    #[serde(rename = "Notes")]
    pub notes: String,

    #[serde(rename = "Attachments")]
    pub attachments: Vec<FileField>,

    #[serde(rename = "Custom")]
    pub custom: Vec<StringField>,
}
