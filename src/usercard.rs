use crate::keycard::*;

static USER_FIELDS: [&EntryFieldType; 12] = [
	&EntryFieldType::Index,
	&EntryFieldType::Name,
	&EntryFieldType::WorkspaceID,
	&EntryFieldType::UserID,
	&EntryFieldType::Domain,
	&EntryFieldType::ContactRequestVerificationKey,
	&EntryFieldType::ContactRequestEncryptionKey,
	&EntryFieldType::EncryptionKey,
	&EntryFieldType::VerificationKey,
	&EntryFieldType::TimeToLive,
	&EntryFieldType::Expires,
	&EntryFieldType::Timestamp,
];

static USER_REQUIRED_FIELDS: [&EntryFieldType; 10] = [
	&EntryFieldType::Index,
	&EntryFieldType::WorkspaceID,
	&EntryFieldType::Domain,
	&EntryFieldType::ContactRequestVerificationKey,
	&EntryFieldType::ContactRequestEncryptionKey,
	&EntryFieldType::EncryptionKey,
	&EntryFieldType::VerificationKey,
	&EntryFieldType::TimeToLive,
	&EntryFieldType::Expires,
	&EntryFieldType::Timestamp,
];

