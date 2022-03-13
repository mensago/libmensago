use std::fmt;

#[derive(Debug)]
pub enum MensagoError {
	ErrEmptyData,
	ErrExists,
	ErrFilesytemError,
	ErrUnimplemented,
}

impl std::error::Error for MensagoError {}

impl fmt::Display for MensagoError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			MensagoError::ErrEmptyData => write!(f, "Empty data error"),
			MensagoError::ErrExists => write!(f, "Resource already exists"),
			MensagoError::ErrFilesytemError => write!(f, "Filesystem error"),
			MensagoError::ErrUnimplemented => write!(f, "Function unimplemented"),
		}
	}
}
