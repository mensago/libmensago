#include <QtTest>

// add necessary includes here

class cryptostring_test : public QObject
{
	Q_OBJECT

public:
	cryptostring_test();
	~cryptostring_test();

private slots:
	void test_case1();

};

cryptostring_test::cryptostring_test()
{

}

cryptostring_test::~cryptostring_test()
{

}

void cryptostring_test::test_case1()
{

}

QTEST_APPLESS_MAIN(cryptostring_test)

#include "tst_cryptostring.moc"
