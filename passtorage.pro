#-------------------------------------------------
#
# Project created by QtCreator 2016-09-05T21:07:58
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = passtorage
TEMPLATE = app


SOURCES += main.cpp\
        widget.cpp \
    datastruct.cpp

HEADERS  += widget.h \
    datastruct.h

FORMS    += widget.ui

INCLUDEPATH = G:/Code/LIBS/OpenSSL/include

LIBS += G:/Code/LIBS/OpenSSL/lib/libcrypto.lib\
    G:/Code/LIBS/OpenSSL/lib/libssl.lib
