QT += testlib
QT -= gui

CONFIG += qt console warn_on depend_includepath testcase
CONFIG -= app_bundle

TEMPLATE = app

SOURCES +=  tst_cryptostring.cpp

win32:CONFIG(release, debug|release): LIBS += -L$$OUT_PWD/../mensago/release/ -lmensago
else:win32:CONFIG(debug, debug|release): LIBS += -L$$OUT_PWD/../mensago/debug/ -lmensago
else:unix: LIBS += -L$$OUT_PWD/../mensago/ -lmensago

INCLUDEPATH += $$PWD/../mensago
DEPENDPATH += $$PWD/../mensago
