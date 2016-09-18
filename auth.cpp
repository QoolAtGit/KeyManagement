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
    QString serNum=getRandomNum(6);
    if(generateAndSaveKey("",serNum.toInt()))
    {
        QString info="序列号为："+serNum;
        QString timer="["+QTime::currentTime().toString()+"] ";
        ui->textBrowser->append(timer+"生成非对称密钥");
        ui->textBrowser->append(timer+info);
        writeLog("生成对称密钥");
        QString path=QDir::currentPath()+"/key/";
        QDesktopServices::openUrl(QUrl(path, QUrl::TolerantMode));
        ui->lineEdit_2->setText(path+"private"+serNum+".pem");
    }
    else
    {
        ui->lineEdit_2->setText("发生错误");
        QString timer="["+QTime::currentTime().toString()+"] ";
        ui->textBrowser->append(timer+"发生错误，生成失败");
    }
}

void Auth::on_pushButton_2_clicked()
{
    emit switchToLogn();
    this->hide();
}
