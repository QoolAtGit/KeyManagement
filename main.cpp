#include "widget.h"
#include "auth.h"
#include "login.h"
#include "datastruct.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    Auth authWin;
    Login loginWindow;
    Widget w;
    QObject::connect(&authWin,&Auth::switchToLogn,&loginWindow,&Login::show);
    QObject::connect(&loginWindow,&Login::switchToBegin,&authWin,&Auth::show);
    QObject::connect(&loginWindow,&Login::switchToWidget,&w,&Widget::show);
    QObject::connect(&loginWindow,&Login::sendPassWord,&w,&Widget::setDataStruct);
    QObject::connect(&w,&Widget::switchTOAuth,&authWin,&Auth::show);
    QString passWord;
    if(loadAuth(passWord)<0)
        authWin.show();
    else
        loginWindow.show();

    return a.exec();
}
