use thiserror::Error;

#[derive(Error, Debug)]
pub enum MensagoError {

	#[error("Empty data error")]
	ErrEmptyData,
	#[error("Resource already exists")]
	ErrExists,
	#[error("Filesystem error")]
	ErrFilesytemError,
	#[error("Not found")]
	ErrNotFound,
	#[error("Reserved")]
	ErrReserved,
	#[error("Function unimplemented")]
	ErrUnimplemented,

	#[error(transparent)]
    IOError(#[from] std::io::Error),
}
