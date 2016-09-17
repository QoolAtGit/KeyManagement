#include <QTime>
#include <QFile>
#include <QFileDialog>
#include "widget.h"
#include "ui_widget.h"
#include "datastruct.h"

Widget::Widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->progressBar->setRange(0,15);
    if(readAccounts(datas.accounts)<0)
    {
        QString timer="["+QTime::currentTime().toString()+"] ";
        ui->textBrowser->append(timer+"文件读取失败1");
    }
    displayAccounts();
}

Widget::~Widget()
{
    delete ui;
}

void Widget::setDataStruct(QString passWord)
{
    datas.enterKey=passWord;
    QFile priFile("./key/private/private10000001.pem");
    QFile pubFile("./key/public/public10000001.pem");
    if(priFile.exists()==false||pubFile.exists()==false)
    {
        if(!generateAndSaveKey(getMd5(passWord),10000001))
            emit switchTOAuth();
    }
    return;
}
void Widget::displayAccounts()
{
    QList<Account>::const_iterator i;
    QStringList header;
    header<<"用户名"<<"密码";
    ui->tableWidget_3->insertColumn(0);
    ui->tableWidget_3->insertColumn(1);
    ui->tableWidget_3->setHorizontalHeaderLabels(header);
    for(i=datas.accounts.constBegin();i!=datas.accounts.constEnd();++i)
    {
        int currentRow=ui->tableWidget_3->rowCount();
        QTableWidgetItem *num0=new QTableWidgetItem(QTableWidgetItem::Type);
        QTableWidgetItem *num1=new QTableWidgetItem(QTableWidgetItem::Type);
        num0->setText(i->userName);
        num1->setText(i->passWord);
        ui->tableWidget_3->insertRow(currentRow);
        ui->tableWidget_3->setItem(currentRow,0,num0);
        ui->tableWidget_3->setItem(currentRow,1,num1);
    }
    ui->tableWidget_3->show();
    return;
}

void Widget::on_pushButton_clicked()
{
    int len=ui->spinBox->value();
    QString keys=getRandomNum(len);
    ui->lineEdit->setText(keys);
    QString timer="["+QTime::currentTime().toString()+"] ";
    ui->textBrowser->append(timer+"生成对称密钥");
    ui->textBrowser->append(timer+keys);
    writeLog("生成对称密钥");
}

void Widget::on_spinBox_valueChanged(int arg1)
{
    QString keys=getRandomNum(arg1);
    ui->lineEdit->setText(keys);
    QString timer="["+QTime::currentTime().toString()+"] ";
    ui->textBrowser->append(timer+"生成对称密钥");
    ui->textBrowser->append(timer+keys);
    writeLog("生成对称密钥");
}

void Widget::on_pushButton_5_clicked()
{
    QString path = QFileDialog::getOpenFileName(this,"选择文件",".");
    if(path.isEmpty())
    {
        ui->label_10->setText("你没有选择任何文件");
        return;
    }
    ui->lineEdit_3->setText(path);
    return;
}

void Widget::on_pushButton_4_clicked()
{
    srcPath=ui->lineEdit_3->text();
    if(srcPath.isEmpty())
    {
        ui->label_10->setText("请选择待签名文件的路径");
        return;
    }
    QString priPath="./key/private/private10000001.pem";
    int ret=signKey(priPath,getMd5(datas.enterKey),srcPath);
    if(ret==-1)
    {
        ui->label_10->setText("文件不存在");
        return;
    }
    else if(ret==0)
    {
        ui->label_10->setText("文件签名成功");
        QString timer="["+QTime::currentTime().toString()+"] ";
        ui->textBrowser->append(timer+"文件签名成功");
        return;
    }
    else
    {
        ui->label_10->setText("文件签名错误");
        return;
    }
}

void Widget::on_lineEdit_5_textChanged(const QString &arg1)
{
    int ret=getSecureLevel(ui->lineEdit_4->text(),arg1);
    if(ret<0)
        ui->progressBar->setValue(0);
    else
        ui->progressBar->setValue(ret);
    return;
}

void Widget::on_lineEdit_4_textChanged(const QString &arg1)
{
    int ret=getSecureLevel(arg1,ui->lineEdit_5->text());
    if(ret<0)
        ui->progressBar->setValue(0);
    else
        ui->progressBar->setValue(ret);
    return;
}

void Widget::on_pushButton_6_clicked()
{
    if(ui->progressBar->value()<0)
    {
        QString timer="["+QTime::currentTime().toString()+"] ";
        ui->textBrowser->append(timer+"安全性太低");
        return;
    }
    Account account;
    account.userName=ui->lineEdit_4->text();
    account.passWord=ui->lineEdit_5->text();
    datas.accounts.append(account);
    if(writeAccounts(datas.accounts)<0)
    {
        QString timer="["+QTime::currentTime().toString()+"] ";
        ui->textBrowser->append(timer+"文件写入错误");
        return;
    }
    QString timer="["+QTime::currentTime().toString()+"] ";
    ui->textBrowser->append(timer+"添加成功");
    ui->tableWidget_3->clear();
    displayAccounts();
}
