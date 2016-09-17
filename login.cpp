#include "login.h"
#include "ui_login.h"
#include "datastruct.h"

Login::Login(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Login)
{
    ui->setupUi(this);
}

Login::~Login()
{
    delete ui;
}

void Login::on_pushButton_clicked()
{
    emit switchToBegin();
    this->hide();
}

void Login::on_pushButton_2_clicked()
{
    QString passWord;
    QString passWordText=ui->lineEdit_2->text();
    if(passWordText.isEmpty())
        return;
    if(loadAuth(passWord)<0)
    {
        if(writeAuth(passWordText)<0)
        {
            ui->label->setText("文件写入失败");
            return;
        }
        emit switchToWidget();
        emit sendPassWord(passWordText);
        this->hide();
        return;
    }
    if(passWord!=passWordText)
    {
        ui->label->setText("密码不一致");
        return;
    }
    emit switchToWidget();
    emit sendPassWord(passWordText);
    this->hide();
    return;
}
