QT -= gui

TEMPLATE = lib
DEFINES += LIBMENSAGO_LIBRARY

CONFIG += c++14

SOURCES += \
	base85.cpp \
	cryptostring.cpp

HEADERS += \
	base85.h \
	cryptostring.h \
	libmensago_global.h

TARGET = mensago

# Default rules for deployment.
unix {
    target.path = /usr/lib
}
!isEmpty(target.path): INSTALLS += target

