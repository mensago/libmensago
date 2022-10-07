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

/// SeparatedStrList represents a group of strings which are separated by a string of some type,
/// e.g. a comma, a colon, etc. The separator may be more than one character, but regardless of the
/// separator, items in the list may not contain the string used as the separator.
#[derive(Debug, PartialEq, PartialOrd, Clone)]
pub struct SeparatedStrList {
    separator: String,
    pub items: Vec<String>,
}

impl SeparatedStrList {
    /// Creates a new instance with the specified separator
    pub fn new(sep: &str) -> SeparatedStrList {
        SeparatedStrList {
            separator: String::from(sep),
            items: Vec::new(),
        }
    }

    pub fn from(s: &str, sep: &str) -> SeparatedStrList {
        if sep.len() == 0 {
            return SeparatedStrList {
                separator: String::new(),
                items: vec![String::from(s)],
            };
        }

        SeparatedStrList {
            separator: String::from(sep),
            items: SeparatedStrList::parse(s, sep),
        }
    }

    /// Returns all items in the list joined by the instance's separator character. No padding is
    /// placed between the items and the separator character. If there are no items in the list,
    /// this method returns an empty string.
    pub fn join(&self) -> String {
        if self.items.len() > 0 {
            self.items.join(&self.separator)
        } else {
            String::new()
        }
    }

    /// `push()` appends a string to the list. This can append one item at a time or it can append
    /// multiple items if given a string containing the separator.
    pub fn push(&mut self, s: &str) -> &mut Self {
        self.items
            .append(&mut SeparatedStrList::parse(s, &self.separator));
        self
    }

    /// `set()` replaces the contents of the list with that of the given string.
    pub fn set(&mut self, s: &str) -> &mut Self {
        self.items.clear();
        self.push(s)
    }

    pub fn set_separator(&mut self, sep: &str) -> &mut Self {
        self.separator = String::from(sep);
        self
    }

    /// Private method which handles separation and formatting.
    /// Remember, kids, Don't Repeat Yourself! 😛
    fn parse(s: &str, sep: &str) -> Vec<String> {
        s.split(&sep)
            .map(|x| x.trim())
            .filter(|x| x.len() > 0)
            .map(|x| String::from(x))
            .collect()
    }
}

impl fmt::Display for SeparatedStrList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.items.len() > 0 {
            write!(f, "{}", self.items.join(&self.separator))
        } else {
            write!(f, "")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{MensagoError, SeparatedStrList};

    #[test]
    fn test_seplist() -> Result<(), MensagoError> {
        // Empty item filtering
        assert_eq!(
            SeparatedStrList::from("a::b::c::d::", "::").join(),
            "a::b::c::d"
        );

        // Duplicate separator filtering
        assert_eq!(
            SeparatedStrList::from("a::b::c::::::d::", "::").join(),
            "a::b::c::d"
        );

        // set()/set_separator()
        assert_eq!(
            SeparatedStrList::from("a:b:c:d:", ":")
                .set_separator("-")
                .set("a::b")
                .join(),
            "a::b"
        );

        // push()
        assert_eq!(
            SeparatedStrList::from("a:b:c:d:", ":")
                .set_separator("-")
                .push("e::f")
                .join(),
            "a-b-c-d-e::f"
        );

        Ok(())
    }
}
