use std::collections::HashMap;
use chrono::prelude::*;
use chrono::{NaiveDate, Duration};
use eznacl::*;
use crate::base::*;
use crate::keycard::*;
use crate::types::*;

#[derive(Debug)]
struct OrgSigBlock {
	signatures: [Option<CryptoString>; 4]
}

impl OrgSigBlock {

	fn astype_to_index(astype: &AuthStrType) -> Result<usize,MensagoError> {

		match astype {
			AuthStrType::User => Err(MensagoError::ErrBadValue),
			AuthStrType::Custody => Ok(0),
			AuthStrType::PrevHash => Ok(1),
			AuthStrType::Hash => Ok(2),
			AuthStrType::Organization => Ok(3),
		}
	}

	fn index_to_astype(index: &usize) -> Result<AuthStrType,MensagoError> {

		match index {
			0 => Ok(AuthStrType::Custody),
			1 => Ok(AuthStrType::PrevHash),
			2 => Ok(AuthStrType::Hash),
			3 => Ok(AuthStrType::Organization),
			_ => Err(MensagoError::ErrBadValue),
		}
	}

	pub fn new() -> OrgSigBlock {
		OrgSigBlock { signatures: [None, None, None, None].clone() }
	}
}

/// The SignatureBlock implementation for OrgSigBlock. This provides the specific handling for
/// organizational signatures, which require signatures and hashes in the following order:
/// 
/// - Custody Signature, required for all entries except a keycard's root entry
/// - Previous Hash, required for all entries except an organization's root keycard entry
/// - Hash, required for all entries
/// - Organization Signature, required for all entries
/// 
/// Note that explicitly calling verify() with the Hash type isn't required because it is 
/// automatically verified when the organizational signature is verified.
impl SignatureBlock for OrgSigBlock {

	fn has_authstr(&self, astype: &AuthStrType) -> Result<bool,MensagoError> {
	
		let index = OrgSigBlock::astype_to_index(astype)?;

		match self.signatures[index] {
			Some(_) => Ok(true),
			None => Ok(false)
		}
	}

	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError> {

		let index = OrgSigBlock::astype_to_index(astype)?;

		match &self.signatures[index] {
			Some(v) => Ok(v.clone()),
			None => Err(MensagoError::ErrNotFound)
		}
	}

	fn get_text(&self, aslevel: &AuthStrType) -> Result<Vec::<CryptoString>, MensagoError> {
		
		let mut out = Vec::<CryptoString>::new();
		let lastindex = OrgSigBlock::astype_to_index(aslevel)?;
		for item in self.signatures.iter().enumerate() {
			
			if item.0 > lastindex {
				break
			}
			
			match item.1 {
				Some(v) => out.push(v.clone()),
				None => { /* Do nothing */ },
			};
		}
		
		Ok(out)
	}

	fn add_authstr(&mut self, astype: &AuthStrType, astr: &CryptoString)
		-> Result<(), MensagoError> {

		let index = OrgSigBlock::astype_to_index(astype)?;

		self.signatures[index] = Some(astr.clone());
		
		Ok(())
	}
	
	fn hash(&mut self, entry: &str, algorithm: &str) -> Result<(), MensagoError> {

		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));

		let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody)?;
		match &self.signatures[index] {
			Some(v) => {
				strings.push(v.to_string())
			},
			None => { /* Do nothing if the custody signature doesn't exist */ },
		};
		index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash)?;
		match &self.signatures[index] {
			Some(v) => {
				strings.push(v.to_string())
			},
			None => { /* Not a big deal if the previous hash field doesn't exist */ },
		};

		let totaldata = strings.join("\r\n");
		
		let hash = get_hash(algorithm, totaldata.as_bytes())?;
		self.add_authstr(&AuthStrType::Hash, &hash)
	}

	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_pair: &SigningPair)
		-> Result<(), MensagoError> {
		
		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));

		match astype {
			AuthStrType::User => {
				// Calling the User signature type on an org card indicates a bug in the caller's
				// code
				return Err(MensagoError::ErrBadValue)
			},
			AuthStrType::Custody => {
				/* For the custody signature, we don't need to do anything extra */
			},
			AuthStrType::PrevHash => {
				// This method should never be called with the PrevHash type becuase it makes no
				// sense. Instead, add_authstr() should be called to populate the PrevHash field
				return Err(MensagoError::ErrOutOfOrderSignature)
			},
			AuthStrType::Hash => {
				// This method should never be called with the Hash type because that's what the
				// hash() method is for and is the sign of a bug in the caller's code.
				return Err(MensagoError::ErrOutOfOrderSignature)
			},
			AuthStrType::Organization => {
				// The org signature on org cards is the final field, so make sure that we have all
				// other hashes and signatures included in the verification data if they exist
				let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrOutOfOrderSignature)
					},
				};
			}
		};

		let totaldata = strings.join("\r\n");
		let signature = signing_pair.sign(totaldata.as_bytes())?;

		self.add_authstr(&AuthStrType::Organization, &signature)
	}

	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature) 
		-> Result<(), MensagoError> {
		
		let mut strings = Vec::<String>::new();
		strings.push(String::from(entry));
	
		let sig = match astype {
			AuthStrType::User => {
				// Calling the User signature type on an org card indicates a bug in the caller's
				// code
				return Err(MensagoError::ErrBadValue)
			},
			AuthStrType::Custody => {

				let index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::PrevHash => {

				// It's silly to try to verify the previous hash because there's nothing to verify,
				// but if someone accidentally calls verify() with this type, it's not hurting
				// anything, so we'll just return Ok.
				return Ok(())
			},
			AuthStrType::Hash => {

				// Calling verify() with the Hash type isn't necessary because the hash is also
				// verified when the organizational signature is verified, but if someone really
				// wants to do this, we'll humor them. ;)
				
				// The Hash field includes the Custody Signature and PrevHash fields if present
				let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
			AuthStrType::Organization => {
				
				// The org signature on org cards is the final field, so make sure that we have all
				// other hashes and signatures included in the verification data if they exist
				let mut index = OrgSigBlock::astype_to_index(&AuthStrType::Custody).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Do nothing if the custody signature doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::PrevHash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { /* Not a big deal if the previous hash field doesn't exist */ },
				};
				index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				match &self.signatures[index] {
					Some(v) => {
						strings.push(v.to_string())
					},
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				index = OrgSigBlock::astype_to_index(astype)?;
				match &self.signatures[index] {
					Some(v) => v,
					None => return Err(MensagoError::ErrNotFound),
				}
			},
		};
		
		let totaldata = strings.join("\r\n");
		
		// Verify the Hash field when verification of the Hash or Organization fields is requested
		match *astype {
			AuthStrType::Hash => {
				let hash = get_hash(sig.prefix(), totaldata.as_bytes())?;
				return if hash == *sig {
					Ok(())
				} else {
					Err(MensagoError::ErrInvalidKeycard)
				}
			}			
			AuthStrType::Organization => {
				let index = OrgSigBlock::astype_to_index(&AuthStrType::Hash).unwrap();
				let cardhash = match &self.signatures[index] {
					Some(v) => v,
					None => { 
						// It does matter if the hash hasn't yet been generated. Although we *could*
						// just do it here, the caller may have requirements on which algorithm is
						// used, e.g BLAKE2 is not FIPS140-3 compliant even if it is secure.
						return Err(MensagoError::ErrNotFound)
					},
				};

				let hash = get_hash(cardhash.prefix(), totaldata.as_bytes())?;
				if hash == *cardhash {
					/* Continue on to signature verification */
				} else {
					return Err(MensagoError::ErrInvalidKeycard)
				}
			},
			_ => { /* Do nothing for the other types */},
		}

		if verify_key.verify(totaldata.as_bytes(), &sig)? {
			Ok(())
		} else {
			Err(MensagoError::ErrInvalidKeycard)
		}
	}
}

// OrgEntry is an entry for an organizational keycard
struct OrgEntry {
	_type: EntryType,
	fields: HashMap<EntryFieldType, Box<dyn VerifiedString>>,
	sigs: OrgSigBlock,
}


static ORG_REQUIRED_FIELDS: [&EntryFieldType; 7] = [
	&EntryFieldType::Index,
	&EntryFieldType::Name,
	&EntryFieldType::ContactAdmin,
	&EntryFieldType::PrimaryVerificationKey,
	&EntryFieldType::TimeToLive,
	&EntryFieldType::Expires,
	&EntryFieldType::Timestamp,
];

impl OrgEntry {

	/// Creates a new, empty OrgEntry
	pub fn new() -> OrgEntry {
		let mut out = OrgEntry {
			_type: EntryType::Organization,
			fields: HashMap::<EntryFieldType, Box<dyn VerifiedString>>::new(),
			sigs: OrgSigBlock::new(),
		};

		// Set some default values to save the caller some time.
		out.set_field(&EntryFieldType::TimeToLive, &String::from("14")).unwrap();
		out.set_field(&EntryFieldType::Timestamp, &get_timestamp()).unwrap();

		let in_one_year = get_offset_date(Duration::days(365))
			.expect("Unable to create date 365 days from now");
		out.set_field(&EntryFieldType::Expires,&in_one_year).unwrap();
		
		out
	}

	/// Creates a new OrgEntry from string data. Note that unlike most libmensago from() calls, 
	/// this version returns a Result, not an option. This is to provide a better experience for the
	/// caller -- a keycard's data can be invalid for a lot of different reasons and returning an
	/// error will aid debugging. Note that compliance of the keycard is not guaranteed if this 
	/// function returns success; it only ensures that all fields are valid and have data which
	/// conforms to the expected formats.
	pub fn from(s: &str) -> Result<OrgEntry, MensagoError> {

		// 160 is a close approximation. It includes the names of all required fields and the
		// minimum length for any variable-length fields, including keys. It's a good quick way of
		// ruling out obviously bad data.
		if s.len() < 160 {
			return Err(MensagoError::ErrBadValue)
		}

		let mut out = OrgEntry::new();
		for line in s.split("\r\n") {

			if line.len() == 0 {
				continue
			}

			let trimmed = line.trim();
			if trimmed.len() == 0 {
				continue
			}


			let parts = trimmed.splitn(2, ":").collect::<Vec<&str>>();
			if parts.len() != 2 {
				return Err(MensagoError::ErrBadFieldValue(String::from(trimmed)))
			}

			let field_value = match parts.get(1) {
				Some(v) => v.clone(),
				None => { return Err(MensagoError::ErrBadFieldValue(String::from(parts[0]))) },
			};

			match AuthStrType::from(parts[0]) {
				Some(ast) => {
					
					match CryptoString::from(field_value) {
						Some(cs) => {
							out.sigs.add_authstr(&ast, &cs)?;
							continue
						},
						None => {
							return Err(MensagoError::ErrBadFieldValue(String::from(parts[0])))
						}
					}
				},
				None => { /* A different field type. Just move on. */ },
			}

			let field_type = match EntryFieldType::from(parts[0]) {
				Some(v) => v,
				None => return Err(MensagoError::ErrUnsupportedField)
			};
			
			if field_type == EntryFieldType::Type {
				if field_value != "Organization" {
					return Err(MensagoError::ErrUnsupportedKeycardType)
				}
				continue
			}

			match out.set_field(&field_type, field_value) {
				Ok(_) => { /* */ },
				Err(e) => {
					return Err(e)	
				}
			}
		}

		Ok(out)
	}

	fn has_authstr(&self, astype: &AuthStrType) -> Result<bool, MensagoError> {
		self.sigs.has_authstr(astype)
	}

	/// Returns the specified authentication string
	fn get_authstr(&self, astype: &AuthStrType) -> Result<CryptoString, MensagoError> {
		self.sigs.get_authstr(astype)
	}

	/// Sets the specified authentication string to the value passed. NOTE: no validation of the
	/// authentication string is performed by this call. The primary use for this method is to set
	/// the previous hash for the signature block
	fn add_authstr(&mut self, astype: &AuthStrType, astr: &CryptoString)
		-> Result<(), MensagoError> {
		
		self.sigs.add_authstr(astype, astr)
	}

	/// Calculates the hash for the entry text using the specified algorithm. Requirements for this
	/// call vary with the entry implementation. ErrOutOfOrderSignature is returned if a hash is
	/// requested before another required authentication string has been set.
	fn hash(&mut self, algorithm: &str) -> Result<(), MensagoError> {

		// TODO: Finish implementing OrgEntry::hash()
		// let text = self.get_text(None);
		// self.sigs.hash(&text, algorithm)
		Err(MensagoError::ErrUnimplemented)
	}

	/// Creates the requested signature. Requirements for this call vary with the entry
	/// implementation. ErrOutOfOrderSignature is returned if a signature is requested before
	/// another required authentication string has been set. ErrBadValue is returned for a
	/// signature type not used by the specific implementation.
	fn sign(&mut self, entry: &str, astype: &AuthStrType, signing_key: &SigningPair)
		-> Result<(), MensagoError> {
		
		// TODO: Implement OrgEntry::verify
		Err(MensagoError::ErrUnimplemented)
	}
	
	/// Verifies the requested signature. ErrBadValue is returned for a signature type not used by
	/// the specific implementation.
	fn verify(&mut self, entry: &str, astype: &AuthStrType, verify_key: &dyn VerifySignature)
		-> Result<(), MensagoError> {
		
		// TODO: Implement OrgEntry::verify
		Err(MensagoError::ErrUnimplemented)
	}
}

impl KeycardEntry for OrgEntry {

	fn get_type(&self) -> EntryType {
		self._type
	}
	
	fn get_field(&self, field: &EntryFieldType) -> Result<String, MensagoError> {

		match self.fields.get(field) {
			Some(v) => {
				Ok(String::from(v.get()))
			},
			None => {
				Err(MensagoError::ErrNotFound)
			}
		}
	}

	fn set_field(&mut self, field: &EntryFieldType, value: &str) -> Result<(), MensagoError> {

		match field {
			EntryFieldType::Type => { 
				// The Type field doesn't get put into the field index, so just return OK.
				return Ok(())
			},
			EntryFieldType::Index => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Name => { /* Field is OK. Do nothing. */ },
			EntryFieldType::ContactAdmin => { /* Field is OK. Do nothing. */ },
			EntryFieldType::ContactAbuse => { /* Field is OK. Do nothing. */ },
			EntryFieldType::ContactSupport => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Language => { /* Field is OK. Do nothing. */ },
			EntryFieldType::PrimaryVerificationKey => { /* Field is OK. Do nothing. */ },
			EntryFieldType::SecondaryVerificationKey => { /* Field is OK. Do nothing. */ },
			EntryFieldType::EncryptionKey => { /* Field is OK. Do nothing. */ },
			EntryFieldType::TimeToLive => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Expires => { /* Field is OK. Do nothing. */ },
			EntryFieldType::Timestamp => { /* Field is OK. Do nothing. */ },
			_ => {
				return Err(MensagoError::ErrBadFieldValue(field.to_string()))
			}
		}

		match EntryFieldType::new_field(field, value) {
			Some(v) => {
				let _ = self.fields.insert(*field, v);
			},
			None => {
				return Err(MensagoError::ErrBadFieldValue(String::from(field.to_string())))
			}
		}
		Ok(())
	}

	fn set_fields(&mut self, fields: &Vec<(EntryFieldType, String)>) -> Result<(), MensagoError> {

		if fields.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}
		
		// I'm sure there's a more compact way to do this, but I can't figure out what it would be.
		// :(
		for (k, v) in fields.iter() {
			match EntryFieldType::new_field(k, v) {
				Some(v) => {
					let _ = self.fields.insert(*k, v);
				},
				None => {
					return Err(MensagoError::ErrBadValue)
				}
			}
		}
		
		Ok(())
	}

	fn set_fields_str(&mut self, fields: &Vec<(String, String)>) -> Result<(), MensagoError> {

		if fields.len() < 1 {
			return Err(MensagoError::ErrEmptyData)
		}
		
		for (k, v) in fields.iter() {
			match EntryFieldType::from(k) {
				Some(ft) => {
					match EntryFieldType::new_field(&ft, v) {
						Some(fieldval) => {
							let _ = self.fields.insert(ft, fieldval);
						},
						None => {
							return Err(MensagoError::ErrBadValue)
						}
					}
			
				},
				None => {
					return Err(MensagoError::ErrBadValue)
				}
			};
		}
		
		Ok(())
	}

	fn delete_field(&mut self, field: &EntryFieldType) -> Result<(), MensagoError> {

		let _ = self.fields.remove(field);
		Ok(())
	}

	fn is_data_compliant(&self) -> Result<bool, MensagoError> {

		// Ensure that all required fields are present. Because each field is a ValidatedString, we
		// already know that if the field is present, it's valid, too. :)
		for f in ORG_REQUIRED_FIELDS {
			match self.fields.get(f) {
				Some(_) => { /* do nothing */ },
				None => {
					return Ok(false)
				}
			}
		}

		Ok(true)
	}

	fn is_compliant(&self) -> Result<bool, MensagoError> {

		let status = self.is_data_compliant()?;
		if !status {
			return Ok(status);
		}

		// The Custody signature and the PrevHash field are both required if the entry is not the
		// root entry of the org's keycard.
		let entry_index = match self.fields.get(&EntryFieldType::Index) {
			Some(v) => {
				match v.get().parse::<u32>() {
					Ok(i) => i,
					Err(e) => {
						// We should never be here
						return Err(MensagoError::ErrProgramException(e.to_string()))
					},
				}
			},
			None => {
				return Ok(false)
			}
		};

		if entry_index > 0 {
			match OrgSigBlock::astype_to_index(&AuthStrType::Custody) {
				Ok(_) => { /* Do nothing*/ },
				Err(_) => return Ok(false)
			}
			match OrgSigBlock::astype_to_index(&AuthStrType::PrevHash) {
				Ok(_) => { /* Do nothing*/ },
				Err(_) => return Ok(false)
			}
		}

		match OrgSigBlock::astype_to_index(&AuthStrType::Hash) {
			Ok(_) => { /* Do nothing*/ },
			Err(_) => return Ok(false)
		}

		match OrgSigBlock::astype_to_index(&AuthStrType::Custody) {
			Ok(_) => Ok(true),
			Err(_) => Ok(false)
		}
	}

	fn set_expiration(&mut self, numdays: Option<&u16>) -> Result<(), MensagoError> {

		let count = match numdays {
			Some(v) => {
				// The expiration date may be no longer than 3 years
				if *v > 1095 {
					return Err(MensagoError::ErrBadValue)
				}
				*v
			},
			None => {
				if self._type == EntryType::Organization {
					365
				} else {
					90
				}
			}
		};

		self.set_field(&EntryFieldType::Expires, &count.to_string())?;

		Ok(())
	}

	/// Returns true if the entry has exceeded its expiration date
	fn is_expired(&self) -> Result<bool, MensagoError> {

		// Yes, it would make more sense to simply have a stored value which was already parsed,
		// but the necessary code to do the dynamic dispatch to handle this would probably increase
		// complexity by an order of magnitude. We'll sacrifice a tiny bit of performance for 
		// simplicity.
		let expdate = match self.fields.get(&EntryFieldType::Expires) {
			Some(v) => {
				match NaiveDate::parse_from_str(v.get(), "%Y%m%d") {
					Ok(d) => d,
					Err(e) => {
						// We should never be here
						return Err(MensagoError::ErrProgramException(e.to_string()))
					}
				}
			},
			None => {
				return Err(MensagoError::ErrNotFound)
			}
		};

		let now = Utc::now().date().naive_utc();

		if now > expdate {
			Ok(true)
		} else {
			Ok(false)
		}
	}
	
	/// Returns the entire text of the entry minus any signatures or hashes
	fn get_text(&self, signature_level: Option<&AuthStrType>) -> Result<String, MensagoError> {
		
		let mut lines = Vec::<String>::new();
		
		// First line of an entry must be the type
		lines.push(String::from("Type:")+&self._type.to_string());

		for (k,v) in self.fields.iter() {
			let parts = [k.to_string(), v.get().to_string()];
			lines.push(parts.join(":"));
		}

		match signature_level {
			Some(v) => {
				lines.extend(self.sigs.get_text(v)?
				.iter()
				.map(|x| x.to_string()));
			},
			None => { /* Do nothing */ }
		}

		Ok(lines.join("\r\n"))
	}
}

#[cfg(test)]
mod tests {
	use crate::*;
	use eznacl::*;
	use std::env;
	use std::fs;
	use std::path::PathBuf;
	use std::str::FromStr;

	// Sets up the path to contain the profile tests
	fn setup_test(name: &str) -> PathBuf {
		if name.len() < 1 {
			panic!("Invalid name {} in setup_test", name);
		}
		let args: Vec<String> = env::args().collect();
		let test_path = PathBuf::from_str(&args[0]).unwrap();
		let mut test_path = test_path.parent().unwrap().to_path_buf();
		test_path.push("testfiles");
		test_path.push(name);

		if test_path.exists() {
			fs::remove_dir_all(&test_path).unwrap();
		}
		fs::create_dir_all(&test_path).unwrap();

		test_path
	}

	#[test]
	fn orgentry_from_datacompliant() -> Result<(), MensagoError> {

		let good_carddata = concat!(
			"Type:Organization\r\n",
			"Index:2\r\n",
			"Name:Acme, Inc.\r\n",
			"Contact-Admin:11111111-2222-2222-2222-333333333333/acme.com\r\n",
			"Contact-Support:11111111-2222-2222-2222-444444444444/acme.com\r\n",
			"Contact-Abuse:11111111-2222-2222-2222-555555555555/acme.com\r\n",
			"Language:en\r\n",
			"Primary-Verification-Key:ED25519:&JEq)5Ktu@jfM+Sa@+1GU6E&Ct2*<2ZYXh#l0FxP\r\n",
			"Secondary-Verification-Key:ED25519:&JEq)5Ktu@jfM+Sa@+1GU6E&Ct2*<2ZYXh#l0FxP\r\n",
			"Encryption-Key:CURVE25519:^fI7bdC(IEwC#(nG8Em-;nx98TcH<TnfvajjjDV@\r\n",
			"Time-To-Live:14\r\n",
			"Expires:20231231\r\n",
			"Timestamp:20220501T1352Z\r\n",
			"Custody-Signature:ED25519:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbw\r\n",
			"Previous-Hash:BLAKE2B-256:tSl@QzD1w-vNq@CC-5`($KuxO0#aOl^-cy(l7XXT\r\n",
			"Hash:BLAKE2B-256:6XG#bSNuJyLCIJxUa-O`V~xR{kF4UWxaFJvPvcwg\r\n",
			"Organization-Signature:ED25519:x3)dYq@S0rd1Rfbie*J7kF{fkxQ=J=A)OoO1WGx97o-utWtfbw\r\n");
		

		let entry = match crate::orgcard::OrgEntry::from(good_carddata) {
			Ok(v) => { v },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_datacompliant failed on good data: {}", e.to_string())))
			}
		};

		match entry.is_data_compliant() {
			Ok(v) => {
				if !v {
					return Err(MensagoError::ErrProgramException(
						String::from("orgentry_set_datacompliant failed compliant data")))
				}
			},
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_datacompliant error on compliant data: {}", e.to_string())))
			}
		}

		Ok(())
	}

	#[test]
	fn orgentry_set_get_field() -> Result<(), MensagoError> {
		
		let mut entry = crate::orgcard::OrgEntry::new();

		// Try setting a bad field value
		match entry.set_field(&EntryFieldType::Domain, "/123*") {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_field passed an invalid value")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		// Try setting a field which isn't used for organizations
		match entry.set_field(&EntryFieldType::UserID, "csimons") {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_field allowed an invalid entry type")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		// Try setting a good field value
		match entry.set_field(&EntryFieldType::Name, "Corbin Simons") {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_field failed: {}", e.to_string())))
			}
		}

		// Try getting a field which doesn't exist
		match entry.get_field(&EntryFieldType::Domain) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_get_field passed a nonexistent field")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		// Try getting a field, expecting success here
		match entry.get_field(&EntryFieldType::Name) {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_get_field failed: {}", e.to_string())))
			}
		}

		Ok(())
	}

	#[test]
	fn orgentry_set_fields() -> Result<(), MensagoError> {
		
		let mut entry = crate::orgcard::OrgEntry::new();

		let mut testdata = vec![
			(EntryFieldType::Name, String::from("Example, Inc.")),
			(EntryFieldType::ContactAdmin, String::from("example.com")),
		];
		
		match entry.set_fields(&testdata) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields passed an invalid value")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		testdata = vec![
			(EntryFieldType::Name, String::from("Example, Inc.")),
			(EntryFieldType::ContactAdmin, String::from("11111111-1111-1111-1111-111111111111/example.com")),
		];
		match entry.set_fields(&testdata) {
			Ok(_) => Ok(()),
			Err(e) => {
				Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields failed: {}", e.to_string())))
			}
		}
	}

	#[test]
	fn orgentry_set_fields_str() -> Result<(), MensagoError> {
		
		let mut entry = crate::orgcard::OrgEntry::new();

		let mut testdata = vec![
			(String::from("Name"), String::from("Example, Inc.")),
			(String::from("contactAdmin"),
				String::from("11111111-1111-1111-1111-111111111111/example.com")),
		];
		
		match entry.set_fields_str(&testdata) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields_str passed an invalid key")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		testdata = vec![
			(String::from("Name"), String::from("Example, Inc.")),
			(String::from("Contact-Admin"),
				String::from("11111111-1111-1111-1111-111111111111/example.com")),
		];
		match entry.set_fields_str(&testdata) {
			Ok(_) => Ok(()),
			Err(e) => {
				Err(MensagoError::ErrProgramException(
					format!("orgentry_set_fields_str failed: {}", e.to_string())))
			}
		}
	}

	#[test]
	fn orgentry_delete_field() -> Result<(), MensagoError> {
		
		let mut entry = crate::orgcard::OrgEntry::new();

		// Setup
		match entry.set_field(&EntryFieldType::Name, "Corbin Simons") {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field failed: {}", e.to_string())))
			}
		}

		// Make sure we can get the field
		match entry.get_field(&EntryFieldType::Name) {
			Ok(_) => { /* Test condition passes. Do nothing. */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field failed to get field: {}", e.to_string())))
			}
		}

		// Remove it
		match entry.delete_field(&EntryFieldType::Name) {
			Ok(_) => {
				/* Test condition passes. Do nothing. */
			},
			Err(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field failed to delete a field")))
			}
		}
		
		// Make sure the field doesn't exist anymore
		match entry.get_field(&EntryFieldType::Name) {
			Ok(_) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_delete_field didn't actually delete the test field")))
			},
			Err(_) => {
				/* Test condition passes. Do nothing. */
			}
		}

		Ok(())
	}

	#[test]
	fn orgentry_is_compliant() -> Result<(), MensagoError> {

		let mut entry = crate::orgcard::OrgEntry::new();
		
		let primary_keypair = match eznacl::SigningPair::generate() {
			Some(v) => v,
			None => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_is_compliant: failed to generate primary keypair")))
			},
		};
		let secondary_keypair = match eznacl::SigningPair::generate() {
			Some(v) => v,
			None => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_is_compliant: failed to generate secondary keypair")))
			},
		};
		let encryption_keypair = match eznacl::EncryptionPair::generate() {
			Some(v) => v,
			None => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_is_compliant: failed to generate encryption keypair")))
			},
		};

		let carddata = vec![
			(EntryFieldType::Name, String::from("Example, Inc.")),
			(EntryFieldType::ContactAdmin, 
				String::from("11111111-2222-2222-2222-333333333333/acme.com")),
			(EntryFieldType::ContactSupport, 
				String::from("11111111-2222-2222-2222-444444444444/acme.com")),
			(EntryFieldType::ContactAbuse, 
				String::from("11111111-2222-2222-2222-555555555555/acme.com")),
			(EntryFieldType::Language, String::from("en")),
			(EntryFieldType::PrimaryVerificationKey, primary_keypair.get_public_str()),
			(EntryFieldType::SecondaryVerificationKey, secondary_keypair.get_public_str()),
			(EntryFieldType::EncryptionKey, encryption_keypair.get_public_str()),
			(EntryFieldType::Expires, String::from("20250601")),
			(EntryFieldType::Timestamp, String::from("20220520T1200Z"))
		];
		match entry.set_fields(&carddata) {
			Ok(_) => { /* fields are set as expected */ },
			Err(e) => {
				return Err(MensagoError::ErrProgramException(
					format!("orgentry_is_compliant: failed to set entry fields: {}", e.to_string())))
			}
		}

		// TODO: Finish orgentry_is_compliant() test
		
		Ok(())
	}
}
