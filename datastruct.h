#ifndef DATASTRUCT_H
#define DATASTRUCT_H

#include <QString>
#include <QList>

enum KeysType
{
    SYMMETRIC_KEY,//对称密钥
    ASYMMETRIC_KEY//非对称密钥
};
typedef struct
{
    QString userName;
    QString passWord;
}Account;
typedef struct
{
    QString privateKey;
    QString publicKey;
    QString fileUrl;
    KeysType keyType;
}Savekey;
typedef struct
{
    QList<Savekey> keys;
    QList<Account> accounts;
    QString enterKey;
}DataStruct;

int testFunction(DataStruct &datas);
int readKeys(QList<Savekey> &lists);
int writeKeys(QList<Savekey> &lists);
int readAccounts(QList<Account> &lists);
int writeAccounts(QList<Account> &lists);
int loadLog(QString &info);
int writeLog(QString info);
int loadAuth(QString &auth);
int writeAuth(QString auth);
QString getRandomNum(int len);
QString getMd5(const QString &src);
int getSecureLevel(const QString &userName,const QString &passWord);
bool generateAndSaveKey(const QString passWord,const quint32 id);
int signKey(const QString priPath,const QString passWord,const QString srcPath);
int verifySign(const QString pubPath,const QString passWord,const QString srcPath);

#endif // DATASTRUCT_H
