#include "cryptostring.h"
#include "base85.h"

#include <QStringList>


QRegularExpression CryptoString::sCryptoStringPattern = QRegularExpression(
	"^([A-Z0-9-]{1,24}):([0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~]+)$");
QRegularExpression CryptoString::sCryptoStringPrefixPattern = QRegularExpression(
	"^([A-Z0-9-]{1,24})$");


CryptoString::CryptoString(const char *from):
	fIsValid(Set(from))
{
}

CryptoString::CryptoString(const QString &from):
	fIsValid(Set(from))
{
}

CryptoString::CryptoString(const QString &algorithm, const QByteArray &from):
	fIsValid(false),
	fSplitPoint(0)
{
	if (algorithm.length() == 0 || from.length() == 0) return;
	if (!sCryptoStringPrefixPattern.match(from).hasMatch()) return;
	
	QString encodedData;
	base85encode(from, encodedData);
	fString = algorithm + QString(":") + encodedData;
}

//! Returns true only if the object's data is valid.
bool CryptoString::IsValid() const
{
	return fIsValid;
}

//! AsString returns the prefix and encoded data for the object.
QString &CryptoString::AsString()
{
	return fString;
}

//! Data() returns the prefix for the encoded data.
QString CryptoString::Prefix() const
{
	// This isn't a call that is used often, so we can afford to be a bit less efficient.
	return fString.first(fSplitPoint);
}

//! Data() returns the encoded data portion of the object.
QString CryptoString::Data() const
{
	// This isn't a call that is used often, so we can afford to be a bit less efficient.
	return fString.last(fString.length() - fSplitPoint);
}

//! GetRaw() returns the object's raw, decoded data.
void CryptoString::GetRaw(QByteArray &out) const
{
	base85decode(fString, out);
}

bool CryptoString::Set(const QString &from)
{
	if (!sCryptoStringPattern.match(from).hasMatch())
	{
		return false;
	}
	
	QStringList parts = from.split(":");
	fSplitPoint = parts[0].length();
	fString = from;
	fIsValid = true;

	return true;
}
