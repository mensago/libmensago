#ifndef CRYPTOSTRING_H
#define CRYPTOSTRING_H

#include<QByteArray>
#include<QRegularExpression>
#include<QString>

class CryptoString
{
public:
	CryptoString(const char *from);
	CryptoString(const QString &from);
	CryptoString(const QString &algorithm, const QByteArray &from);

	bool IsValid() const;

	QString &AsString();

	QString Prefix() const;
	QString Data() const;
	void GetRaw(QByteArray &out) const;

private:
	bool Set(const QString &from);

	static QRegularExpression sCryptoStringPattern;
	static QRegularExpression sCryptoStringPrefixPattern;

	QString fString;
	qsizetype fSplitPoint;
	bool	fIsValid;
};

#endif // CRYPTOSTRING_H
