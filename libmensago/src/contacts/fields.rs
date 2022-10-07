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
    pub family_name: Option<String>,
    #[serde(rename = "AdditionalNames")]
    pub additional_names: Option<Vec<String>>,

    #[serde(rename = "Nicknames")]
    pub nicknames: Option<Vec<String>>,

    #[serde(rename = "Prefix")]
    pub prefix: Option<String>,
    #[serde(rename = "Suffixes")]
    pub suffixes: Option<Vec<String>>,
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
    pub street: Option<String>,
    #[serde(rename = "ExtendedAddress")]
    pub extended: Option<String>,
    #[serde(rename = "Locality")]
    pub locality: Option<String>,
    #[serde(rename = "Region")]
    pub region: Option<String>,
    #[serde(rename = "PostalCode")]
    pub postalcode: Option<String>,
    #[serde(rename = "Country")]
    pub country: Option<String>,

    #[serde(rename = "Preferred")]
    pub preferred: Option<String>,
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

/// The Contact type is used for contact information exchange, such as sending a contact info
/// update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Update")]
    pub update: String,

    #[serde(rename = "EntityType")]
    pub entity_type: String,

    #[serde(rename = "Name")]
    pub name: NameField,

    #[serde(rename = "Gender")]
    pub gender: Option<String>,
    #[serde(rename = "Bio")]
    pub bio: Option<String>,

    #[serde(rename = "Social")]
    pub social: Option<Vec<StringField>>,

    #[serde(rename = "Mensago")]
    pub mensago: Option<Vec<MensagoField>>,

    #[serde(rename = "Keys")]
    pub keys: Option<Vec<KeyField>>,

    #[serde(rename = "Messaging")]
    pub messaging: Option<Vec<StringField>>,

    #[serde(rename = "MailingAddresses")]
    pub addresses: Option<Vec<MailingAddr>>,

    #[serde(rename = "Phone")]
    pub phone: Option<Vec<StringField>>,

    #[serde(rename = "Anniversary")]
    pub anniversary: Option<String>,
    #[serde(rename = "Birthday")]
    pub birthday: Option<String>,

    #[serde(rename = "Email")]
    pub email: Option<Vec<StringField>>,

    #[serde(rename = "Organization")]
    pub organization: Option<String>,
    #[serde(rename = "OrgUnits")]
    pub orgunits: Option<Vec<String>>,
    #[serde(rename = "Title")]
    pub title: Option<String>,

    #[serde(rename = "Categories")]
    pub categories: Option<Vec<String>>,

    #[serde(rename = "Websites")]
    pub websites: Option<Vec<StringField>>,

    #[serde(rename = "Photo")]
    pub photo: Option<PhotoField>,

    #[serde(rename = "Languages")]
    pub languages: Option<Vec<StringField>>,

    #[serde(rename = "Notes")]
    pub notes: Option<String>,

    #[serde(rename = "Attachments")]
    pub attachments: Option<Vec<FileField>>,

    #[serde(rename = "Custom")]
    pub custom: Option<Vec<StringField>>,

    #[serde(rename = "Annotations")]
    pub annotations: Option<Box<Self>>,
}
