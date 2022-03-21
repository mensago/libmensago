#include "cryptostring.h"

#include <QTest>
#include <QByteArray>
#include <QString>

using namespace std;


class TestCryptoString: public QObject
{
	Q_OBJECT
private slots:
	void test_from_parts();
};

void TestCryptoString::test_from_parts()
{
	string faillist[3][2] = {
		{"", ":123456789"},
		{"$ILLEGAL", "123456789"},
		{"TEST", ""}
	};

	for (uint8_t i = 0; i < 3; i++)
	{
		CryptoString cs = CryptoString(QString(faillist[i][0].c_str()),
			QByteArray(faillist[i][1].c_str()));
		if (cs.IsValid())
		{
			qFatal("Parts-based constructor failed on bad input '%s','%s'\n",
				faillist[i][0].c_str(), faillist[i][1].c_str());
		}
	}

	CryptoString cs2 = CryptoString(QString("TEST"), QByteArray("aaaaaa"));
	if (!cs2.IsValid())
	{
		qFatal("Parts-based constructor failed on good input\n");
	}
}

QTEST_MAIN(TestCryptoString)
//#include "cryptostring_test.moc"

