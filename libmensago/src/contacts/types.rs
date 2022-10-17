use crate::base::*;
use std::fmt;
use std::str::FromStr;

/// EntityType reflects the type of entity a contact represents
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum EntityType {
    Individual,
    Organization,
    Group,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EntityType::Individual => write!(f, "individual"),
            EntityType::Organization => write!(f, "organization"),
            EntityType::Group => write!(f, "group"),
        }
    }
}

impl FromStr for EntityType {
    type Err = ();

    fn from_str(input: &str) -> Result<EntityType, Self::Err> {
        match input.to_lowercase().as_str() {
            "individual" => Ok(EntityType::Individual),
            "organization" => Ok(EntityType::Organization),
            "group" => Ok(EntityType::Group),
            _ => Err(()),
        }
    }
}

impl std::convert::TryFrom<&str> for EntityType {
    type Error = MensagoError;
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        match input.to_lowercase().as_str() {
            "individual" => Ok(EntityType::Individual),
            "organization" => Ok(EntityType::Organization),
            "group" => Ok(EntityType::Group),
            _ => Err(MensagoError::ErrBadValue),
        }
    }
}
