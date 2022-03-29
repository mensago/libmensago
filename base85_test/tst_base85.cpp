#include <QtTest>

// add necessary includes here

class base85_test : public QObject
{
	Q_OBJECT

public:
	base85_test();
	~base85_test();

private slots:
	void test_case1();

};

base85_test::base85_test()
{

}

base85_test::~base85_test()
{

}

void base85_test::test_case1()
{

}

QTEST_APPLESS_MAIN(base85_test)

#include "tst_base85.moc"
