#include <QtTest>

#include "cryptostring.h"

class cryptostring_test : public QObject
{
	Q_OBJECT

private slots:
	void test_constructors();

};

void cryptostring_test::test_constructors()
{
	CryptoString cs = CryptoString("CURVE25519:(B2XX5|<+lOSR>_0mQ=KX4o<aOvXe6M`Z5ldINd`");
	QVERIFY2(cs.IsValid(), "CryptoString::test_constructors failed on valid const char * input");
}

QTEST_APPLESS_MAIN(cryptostring_test)

#include "tst_cryptostring.moc"
