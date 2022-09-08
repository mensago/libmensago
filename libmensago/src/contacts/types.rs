use libkeycard::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledString {
	#[serde(rename="Label")]
	pub label: String,
	#[serde(rename="Value")]
	pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledMensagoAddr {
	#[serde(rename="Label")]
	pub label: String,
	
	// TODO: Add serde support to libkeycard types
	
	// #[serde(rename="UserID")]
	// pub uid: UserID,
	// #[serde(rename="Workspace")]
	// pub wid: RandomID,
	// #[serde(rename="Domain")]
	// pub domain: Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
	#[serde(rename="Version")]
	pub version: String,
	#[serde(rename="EntityType")]
	pub entity_type: String,
	#[serde(rename="Source")]
	pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Name {
	#[serde(rename="FormattedName")]
	pub formatted_name: String,

	#[serde(rename="GivenName")]
	pub given_name: String,
	#[serde(rename="FamilyName")]
	pub family_name: String,
	#[serde(rename="AdditionalNames")]
	pub additional_names: Vec<String>,

	#[serde(rename="Nicknames")]
	pub nicknames: Vec<String>,

	#[serde(rename="Prefix")]
	pub prefix: String,
	#[serde(rename="Suffixes")]
	pub suffixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
	#[serde(rename="Header")]
	header: Header,
	
	#[serde(rename="Name")]
	pub name: Name,

	#[serde(rename="Gender")]
	pub gender: String,
	#[serde(rename="Bio")]
	pub bio: String,

	#[serde(rename="Social")]
	pub social: Vec<LabeledString>,
	
	#[serde(rename="Mensago")]
	pub mensago: Vec<LabeledMensagoAddr>,

	// Keys: Vec<HashMap<&str, String>>
	// Messaging: Vec<HashMap<&str, String>>
	// MailingAddresses: Vec<HashMap<&str, String>>
	// Phone: Vec<HashMap<&str, String>>

	// Anniversary: String
	// Birthday: Date
	// E-mail: Vec<HashMap<&str, String>>
	// Organization: String
	// OrgUnits: Vec<String>
	// Title: String

	// Categories: Vec<String>

	// Websites: Vec<HashMap<&str, String>>
	// Photo: HashMap<&str, String>
	// Languages: Vec<String>
	// Notes: String
	// Attachments: Vec<HashMap<&str, String>>
	// Custom: Vec<HashMap<&str, String>>
}