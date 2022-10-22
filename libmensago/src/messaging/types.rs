use crate::base::*;
use std::fmt;
use std::str::FromStr;

/// QuoteType reflects the type of quoting used in a message
#[derive(Debug, PartialEq, PartialOrd, Clone, Copy)]
pub enum QuoteType {
    None,
    Top,
    Bottom,
}

impl fmt::Display for QuoteType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteType::None => write!(f, "none"),
            QuoteType::Top => write!(f, "top"),
            QuoteType::Bottom => write!(f, "bottom"),
        }
    }
}

impl FromStr for QuoteType {
    type Err = ();

    fn from_str(input: &str) -> Result<QuoteType, Self::Err> {
        match input.to_lowercase().as_str() {
            "none" => Ok(QuoteType::None),
            "top" => Ok(QuoteType::Top),
            "bottom" => Ok(QuoteType::Bottom),
            _ => Err(()),
        }
    }
}

impl std::convert::TryFrom<&str> for QuoteType {
    type Error = MensagoError;
    fn try_from(input: &str) -> Result<Self, Self::Error> {
        match input.to_lowercase().as_str() {
            "none" => Ok(QuoteType::None),
            "top" => Ok(QuoteType::Top),
            "bottom" => Ok(QuoteType::Bottom),
            _ => Err(MensagoError::ErrBadValue),
        }
    }
}
