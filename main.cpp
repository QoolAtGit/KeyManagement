#include "widget.h"
#include "datastruct.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    DataStruct datas;
    if(testFunction(datas)<0)
        return -1;
    Widget auth;
    auth.show();
//    Widget w;
//    w.show();

    return a.exec();
}
