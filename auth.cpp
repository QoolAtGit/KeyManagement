#include "auth.h"
#include "ui_auth.h"
#include "datastruct.h"
#include <QTime>
#include <QDir>
#include <QDesktopServices>
#include "login.h"

Auth::Auth(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Auth)
{
    ui->setupUi(this);
}

Auth::~Auth()
{
    delete ui;
}

void Auth::on_pushButton_clicked()
{
    int len=ui->spinBox->value();
    QString keys=getRandomNum(len);
    ui->lineEdit->setText(keys);
    QString timer="["+QTime::currentTime().toString()+"] ";
    ui->textBrowser->append(timer+"生成对称密钥");
    ui->textBrowser->append(timer+keys);
    writeLog("生成对称密钥");
}

void Auth::on_spinBox_valueChanged(int arg1)
{
    QString keys=getRandomNum(arg1);
    ui->lineEdit->setText(keys);
    QString timer="["+QTime::currentTime().toString()+"] ";
    ui->textBrowser->append(timer+"生成对称密钥");
    ui->textBrowser->append(timer+keys);
    writeLog("生成对称密钥");
}

void Auth::on_pushButton_3_clicked()
{
    QString inputStr=ui->lineEdit_2->text();
    if(inputStr=="密钥的密码（默认为空）")
        inputStr.clear();
    if(generateAndSaveKey(inputStr,getRandomNum(6).toInt()))
    {
        QString timer="["+QTime::currentTime().toString()+"] ";
        QString info="私钥密码为："+inputStr;
        ui->textBrowser->append(timer+"生成非对称密钥");
        ui->textBrowser->append(timer+info);
        writeLog("生成对称密钥");
        QString path=QDir::currentPath()+"/key/";
        QDesktopServices::openUrl(QUrl(path, QUrl::TolerantMode));
    }
    else
        ui->lineEdit_2->setText("发生错误");
}

void Auth::on_pushButton_2_clicked()
{
    emit switchToLogn();
    this->hide();
}
