use crate::base::*;
use crate::keycardbase::*;
use crate::orgcard::OrgEntry;
use crate::usercard::UserEntry;

/// A Keycard object is a collection of entries tied together in an authenticated blockchain. It
/// consists of the root entry for the entity all the way through the current entry.
pub struct Keycard {

	_type: EntryType,
	pub entries: Vec<Box<dyn KeycardEntry>>,
}

impl Keycard {
	
	/// Creates a new Keycard of the specified type
	pub fn new(t: &EntryType) -> Keycard {

		Keycard {
			_type: *t,
			entries: Vec::<Box<dyn KeycardEntry>>::new(),
		}
	}

	/// Creates a new keycard entry chain from text.
	pub fn from(data: &str) -> Result<Keycard, MensagoError> {

		// We have to have a card type, so we'll default to the most common one. When we determine
		// what kind of card data we're reading, we can change this to match.
		let mut out = Keycard::new(&EntryType::User);
		let mut card_type = String::from("");
		let mut accumulator = Vec::<&str>::new();
		let mut line_index: usize = 1;
		
		for line in data.split("\r\n") {

			let trimmed = line.trim();

			if trimmed == "----- BEGIN ENTRY -----" {
				accumulator.clear();
			} else if line == "----- END ENTRY -----" {

				let entry: Box<dyn KeycardEntry> = match &*card_type {
					"User" => Box::new(UserEntry::from(&accumulator.join("\r\n"))?),
					"Organization" => Box::new(OrgEntry::from(&accumulator.join("\r\n"))?),
					_ => { return Err(MensagoError::ErrInvalidKeycard) }
				};

				out.entries.push(entry);

			} else {

				let parts = trimmed.splitn(2, ":").collect::<Vec<&str>>();
				if parts.len() != 2 {
					return Err(MensagoError::ErrBadFieldValue(String::from(trimmed)))
				}
				
				let field_name = match parts.get(1) {
					Some(v) => v.clone(),
					None => { return Err(MensagoError::ErrBadFieldValue(
						String::from(format!("Invalid line {}", line_index)))) },
				};

				if field_name == "Type" {
					if card_type.len() > 0 {
						if card_type != parts[1] {
							return Err(MensagoError::ErrBadFieldValue(String::from(
								"entry type does not match keycard type")))
						}
					} else {
						card_type = String::from(parts[1]);

						// We defaulted to the User type, which is the most common case, so change
						// the card type of the outbound variable only if necessary
						if card_type == "Organization" {
							out._type = EntryType::Organization
						}
					}
				}

				accumulator.push(trimmed);
			}

			line_index += 1;
		}

		Ok(out)
	}

	/// Returns the type of entries stored in the keycard
	pub fn get_type(&self) -> EntryType {
		self._type
	}

	/// Returns the entire keycard chain as text
	pub fn get_text(&self) -> Result<String, MensagoError> {

		// TODO: implement Keycard::get_text()
		Err(MensagoError::ErrUnimplemented)
	}

	/// Verifies the keycard's complete chain of entries
	pub fn verify(&self) -> Result<bool, MensagoError>  {

		// TODO: implement Keycard::verify()
		Err(MensagoError::ErrUnimplemented)
	}
}

// TODO: implement function to add entry to the database
// TODO: implement function to get most recent entry from the database
// TODO: implement function to get an entire keycard from the database 
