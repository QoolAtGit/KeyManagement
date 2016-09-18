#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>
#include "datastruct.h"

namespace Ui {
class Widget;
}

class Widget : public QWidget
{
    Q_OBJECT

public:
    explicit Widget(QWidget *parent = 0);
    void setDataStruct(QString passWord);
    void displayAccounts();
    void displayKeys();
    ~Widget();

private slots:
    void on_pushButton_clicked();

    void on_spinBox_valueChanged(int arg1);

    void on_pushButton_5_clicked();

    void on_pushButton_4_clicked();

    void on_lineEdit_5_textChanged(const QString &arg1);

    void on_lineEdit_4_textChanged(const QString &arg1);

    void on_pushButton_6_clicked();

    void on_pushButton_3_clicked();

signals:
    void switchTOAuth();

private:
    Ui::Widget *ui;
    DataStruct datas;
    QString srcPath;
};

#endif // WIDGET_H
