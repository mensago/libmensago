#include <QtTest>

#include "base85.h"

#include <QTest>
#include <QByteArray>
#include <QString>
#include <string>

using namespace std;

class base85_test : public QObject
{
	Q_OBJECT

private slots:
	void encode_decode();

};

void base85_test::encode_decode()
{
	string testlist[8][2] = {
		{"a", "VE"},
		{"aa", "VPO"},
		{"aaa", "VPRn"},
		{"aaaa", "VPRom" },
		{"aaaaa", "VPRomVE"},
		{"aaaaaa", "VPRomVPO"},
		{"aaaaaaa", "VPRomVPRn"},
		{"aaaaaaaa", "VPRomVPRom"}
	};

	for (uint8_t i = 0; i < 8; i++)
	{
		QString encoded;
		base85encode(QByteArray(testlist[i][0].c_str()), encoded);
		if (encoded != QString(testlist[i][1].c_str()))
		{
			qFatal("Base85encode('%s'): wanted '%s', got '%s'\n", testlist[i][0].c_str(),
					testlist[i][1].c_str(), qUtf8Printable(encoded));
		}

		QByteArray decoded;
		base85decode(QString(testlist[i][1].c_str()), decoded);
		if (decoded != QString(testlist[i][0].c_str()))
		{
			qFatal("Base85decode('%s'): wanted '%s', got '%s'\n", testlist[i][1].c_str(),
					testlist[i][0].c_str(), qUtf8Printable(decoded));
		}
	}
}

QTEST_APPLESS_MAIN(base85_test)

#include "tst_base85.moc"
