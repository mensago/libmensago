#include "base85.h"

#include <QTest>
#include <QByteArray>
#include <QString>

/*
	let testlist = [
		("a", "VE"),
		("aa", "VPO" ),
		("aaa", "VPRn" ),
		("aaaa", "VPRom" ),
		("aaaaa", "VPRomVE" ),
		("aaaaaa", "VPRomVPO" ),
		("aaaaaaa", "VPRomVPRn"),
		("aaaaaaaa", "VPRomVPRom")
	];

void base85encode(const QByteArray &ba, QString &out);
bool base85decode(const QString &s, QByteArray &out);

*/

#include <QtTest/QtTest>

class TestBase85: public QObject
{
	Q_OBJECT
private slots:
	void encode();
};


void TestBase85::encode()
{
	QString out;
	base85encode(QByteArray("a"), out);
	QVERIFY(out == QString("VE"));
}

QTEST_MAIN(TestBase85)
#include "base85_test.moc"

