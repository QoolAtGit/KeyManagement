#include <QDir>
#include <QFile>
#include <QTime>
#include <QDebug>
#include <QRegExp>
#include <QDataStream>
#include <QTextStream>
#include <QCryptographicHash>
#include <openssl\evp.h>
#include <openssl\md5.h>
#include <openssl\rsa.h>
#include <openssl\pem.h>
#include <openssl/err.h>
#include "datastruct.h"

///
/// \brief readKeys
/// \param lists
/// \return
/// -2 file no exist
/// -1 open error
///  0 normal
///
int readKeys(QList<Savekey> &lists)
{
    QFile keyList("KeyFile.ds");
    if(keyList.exists()==false)
        return -2;
    if(!keyList.open(QIODevice::ReadOnly))
        return -1;
    QDataStream ds(&keyList);
    ds.setVersion(QDataStream::Qt_5_7);
    int numItem;
    ds>>numItem;
    for(int i=0;i<numItem;i++)
    {
        Savekey item;
        qint32 intTokeyType;
        ds>>item.privateKey>>item.publicKey>>item.fileUrl>>intTokeyType;
        item.keyType=(KeysType)intTokeyType;//maye case error;
        lists.append(item);
    }
    keyList.close();
    return 0;
}
///
/// \brief writeKeys
/// \param lists
/// \return
/// -1 open error
///  0 normal
///
int writeKeys(QList<Savekey> &lists)
{
    QFile keyList("KeyFile.ds");
    if(!keyList.open(QIODevice::WriteOnly|QIODevice::Truncate))
        return -1;
    QDataStream ds(&keyList);
    ds.setVersion(QDataStream::Qt_5_7);
    ds<<(qint32)lists.size();
    for(int i=0;i<lists.size();i++)
        ds<<lists.at(i).privateKey<<lists.at(i).publicKey<<lists.at(i).fileUrl<<(qint32)lists.at(i).keyType;
    keyList.close();
    return 0;
}
///
/// \brief readAccounts
/// \param lists
/// \return
/// -2 file no exist
/// -1 file open error
///  0 normal
///
int readAccounts(QList<Account> &lists)
{
    QFile File("acount.ds");
    if(File.exists()==false)
        return -2;
    if(!File.open(QIODevice::ReadOnly))
        return -1;
    QDataStream ds(&File);
    ds.setVersion(QDataStream::Qt_5_7);
    int size;
    ds>>size;
    for(int i=0;i<size;i++)
    {
        Account item;
        ds>>item.userName>>item.passWord;
        lists.append(item);
    }
    File.close();
    return 0;
}
///
/// \brief writeAccounts
/// \param lists
/// \return
/// -1 file open error
///  0 normal
///
int writeAccounts(QList<Account> &lists)
{
    QFile File("acount.ds");
    if(!File.open(QIODevice::WriteOnly|QIODevice::Truncate))
        return -1;
    QDataStream ds(&File);
    ds.setVersion(QDataStream::Qt_5_7);
    ds<<(qint32)lists.size();
    for(int i=0;i<lists.size();i++)
        ds<<lists.at(i).userName<<lists.at(i).passWord;
    File.close();
    return 0;
}
///
/// \brief loadLog
/// \param info
/// \return
/// -1 read log error
///  0 ok
///
int loadLog(QString &info)
{
    QFile file("OpLog.txt");
    if(!file.open(QIODevice::ReadOnly))
        return -1;
    QTextStream ts(&file);
    info=ts.readAll();
    file.close();
    return 0;
}
///
/// \brief writeLog
/// \param info
/// \return
/// -1 write log error
///  0 ok
int writeLog(QString info)
{
    QFile file("OpLog.txt");
    if(!file.open(QIODevice::WriteOnly|QIODevice::Append))
        return -1;
    QTextStream ts(&file);
    ts<<"["<<QTime::currentTime().toString()<<"] "<<info<<endl;
    file.close();
    return 0;
}
///
/// \brief loadAuth
/// \param auth
/// \return
/// -2 empty account | file no exist
/// -1 file open error
///  0 ok
int loadAuth(QString &auth)
{
    auth.clear();
    QFile file("auth.ds");
    if(file.exists()==false)
        return -2;
    if(!file.open(QIODevice::ReadOnly))
        return -1;
    QDataStream ds(&file);
    ds.setVersion(QDataStream::Qt_5_7);
    ds>>auth;
    if(auth.isNull()||auth.isEmpty())
        return -2;
    file.close();
    return 0;
}
///
/// \brief writeAuth
/// \param auth
/// \return
/// -1 file open error
///  0 ok
int writeAuth(QString auth)
{
    QFile file("auth.ds");
    if(!file.open(QIODevice::WriteOnly|QIODevice::Truncate))
        return -1;
    QDataStream ds(&file);
    ds.setVersion(QDataStream::Qt_5_7);
    ds<<auth;
    file.close();
    return 0;
}
///
/// \brief getRandomNum
/// \param len,number length
/// \return QString,random numbers
///
QString getRandomNum(int len)
{
    QString randNum;
    qsrand(QTime::currentTime().msec());
    for(int i=0;i<len;i++)
    {
        randNum+=QString::number(qrand()%10);
    }
    return randNum;
}
///
/// \brief getMd5
/// \param src
/// \return QString, md5
///
QString getMd5(const QString &src)
{
    return QString("%1").arg(QString(QCryptographicHash::hash(src.toUtf8(),QCryptographicHash::Md5).toHex()));
}
///
/// \brief isSecure
/// \param userName
/// \param passWord
/// \return
/// -3 username same with password
/// -2 password too short
/// -1 password empty
/// 0+ secure level
int getSecureLevel(const QString &userName,const QString &passWord)
{
    QRegExp isRepeat("^(.)\\1*$");
    QRegExp haveUper(".*([A-Z]+).*");
    QRegExp haveLower(".*([a-z]+).*");
    QRegExp haveNum(".*([\\d]+).*");
    QRegExp haveOther(".*([^a-zA-Z0-9]+).*");
    int security=0;
    if(passWord.isEmpty())
        return -1;
    if(passWord.length()<6)
        return -2;
    else if(userName==passWord)
        return -3;
    else if(isRepeat.exactMatch(passWord))
        return -4;
    if(haveUper.exactMatch(passWord))
        security+=1;
    if(haveLower.exactMatch(passWord))
        security+=1;
    if(haveNum.exactMatch(passWord))
        security+=1;
    if(haveOther.exactMatch(passWord))
        security+=1;
    if(passWord.length()>10)
        security+=1;
    if(passWord.length()>15)
        security+=1;
    if(passWord.length()>20)
        security+=1;
    return security;
}

/*void generateRsa(QString src,QString passWord)
{
    #define KEY_LENGTH  2048
    #define PUB_EXP     3
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key

    OpenSSL_add_all_algorithms();

    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    priLen = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char*)malloc(pri_len + 1);//
    pub_key = (char*)malloc(pub_len + 1);//

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    // Get the message to encrypt
    printf("Message to encrypt: ");
    fgets(msg, KEY_LENGTH - 1, stdin);
    msg[strlen(msg) - 1] = '\0';

    // Encrypt the message
    encrypt = (char*)malloc(RSA_size(keypair));
    int encrypt_len;
    err = (char*)malloc(130);
    if ((encrypt_len = RSA_public_encrypt(strlen(msg) + 1, (unsigned char*)msg, (unsigned char*)encrypt, keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        fprintf(stderr, "Error encrypting message: %s\n", err);
        goto free_stuff;
    }
    printf("Encrypt message:");
    for (int i = 0; i < sizeof(encrypt); i++)
    {
        printf("%02X", encrypt[i]);

    }
    cout << endl;
    // Decrypt it
    decrypt = (char*)malloc(encrypt_len);

    if (RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt, keypair, RSA_PKCS1_OAEP_PADDING) == -1) {;
        fprintf(stderr, "Error decrypting message: %s\n", err);
        goto free_stuff;
    }
    printf("Decrypted message: %s\n", decrypt);



    char   msg[KEY_LENGTH / 8];  // Message to encrypt
    char   *encrypt = NULL;    // Encrypted message
    char   *decrypt = NULL;    // Decrypted message
    char   *err;               // Buffer for any error messages

free_stuff:
    RSA_free(keypair);
    BIO_free_all(pub);
    BIO_free_all(pri);
    free(pri_key);
    free(pub_key);
    free(encrypt);
    free(decrypt);
    free(err);
}*/
///
/// \brief generateAndSaveKey
/// \param passWord
/// \param id
/// \return
///  true or false
///
bool generateAndSaveKey(const QString passWord,const quint32 id)
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL,
                    *bp_private = NULL;
    int             bits = 2048;
    unsigned long   e = RSA_F4;
    QDir dir;
    dir.mkpath("./key/private/");
    dir.mkpath("./key/public/");
    QString priName=QString("./key/private/private%1.pem").arg(id);
    QString pubName=QString("./key/public/public%1.pem").arg(id);

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1)
    {
        goto free_all;
    }
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1)
    {
        goto free_all;
    }

    // 2. save public key
    bp_public = BIO_new_file(pubName.toStdString().c_str(), "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1)
    {
        goto free_all;
    }

    // 3. save private key
    bp_private = BIO_new_file(priName.toStdString().c_str(), "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, EVP_des_ede3_ofb(), (unsigned char *)passWord.toStdString().c_str(), passWord.length(), NULL, NULL);

    // 4. free
free_all:
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}
///
/// \brief signKey
/// \param priPath
/// \param passWord
/// \param srcPath
/// \return
/// -6
/// -5
/// -4
/// -3
/// -2
/// -1
/// 0
///
int signKey(const QString priPath,const QString passWord,const QString srcPath)
{
    QDir srcDir(srcPath);
    if(!srcDir.exists())
        srcDir.mkpath(srcPath);
    QFile srcFile(srcPath);
    if(!srcFile.exists())
        return -1;
    if(!srcFile.open(QIODevice::ReadOnly))
        return -2;
    QString srckey=srcFile.readAll();

    RSA *rsa=NULL;
    BIO *bpPrivate=NULL;
    bpPrivate = BIO_new(BIO_s_file());
    if(BIO_read_filename(bpPrivate,priPath.toStdString().c_str())!=1)
    {
        BIO_free(bpPrivate);
        return -3;
    }
    rsa=RSA_new();
    rsa=PEM_read_bio_RSAPrivateKey(bpPrivate,NULL,NULL,(void *)passWord.toStdString().c_str());
    if(rsa==NULL)
    {
        RSA_free(rsa);
        BIO_free(bpPrivate);
        return -4;
    }
    unsigned int len=RSA_size(rsa);
    unsigned char signText[len];
    QString digest=getMd5(srckey);
    if(RSA_sign(NID_md5,(const unsigned char*)digest.toStdString().c_str(),digest.length(),signText,&len,rsa)!=1)
    {
        qDebug()<<ERR_reason_error_string(ERR_get_error());
        RSA_free(rsa);
        BIO_free(bpPrivate);
        return -5;
    }
    RSA_free(rsa);
    BIO_free(bpPrivate);

    QString dstPath("./key/signatures/");
    QDir dstDir;
    dstDir.mkpath(dstPath);
    QFileInfo fileInfo(srcPath);
    QString dstName=fileInfo.baseName()+".ds";
    QFile signFile(dstPath+dstName);
    if(!signFile.open(QIODevice::WriteOnly))
        return -6;
    QDataStream ds(&signFile);
    ds.setVersion(QDataStream::Qt_5_7);
    ds<<0x01<<101<<srckey<<digest<<len;
    ds.writeBytes((char*)signText,len);
    return 0;
}
///
/// \brief verifySign
/// \param priPath
/// \param passWord
/// \param srcPath
/// \return
///
int verifySign(const QString pubPath,const QString passWord,const QString srcPath)
{
    QDir srcDir(srcPath);
    if(!srcDir.exists())
        srcDir.mkpath(srcPath);
    QFile signFile(srcPath);
    if(!signFile.exists())
        return -1;
    if(!signFile.open(QIODevice::ReadOnly))
        return -2;
    QDataStream ds(&signFile);
    ds.setVersion(QDataStream::Qt_5_7);
    qint32 magicNum;
    qint32 version;
    QString srckey;
    QString digest;
    int len;
    ds>>magicNum;
    if(magicNum!=0x01)
        return -3;
    ds>>version;
    if(version!=101)
        return -4;
    ds>>srckey>>digest>>len;
    char signText[len];
    ds.readRawData(signText,len);

    RSA *rsa=NULL;
    BIO *bpPublic=NULL;
    bpPublic = BIO_new(BIO_s_file());
    if(BIO_read_filename(bpPublic,pubPath.toStdString().c_str())!=1)
    {
        BIO_free(bpPublic);
        return -5;
    }
    rsa=RSA_new();
    rsa=PEM_read_bio_RSAPublicKey(bpPublic,NULL,NULL,(void *)passWord.toStdString().c_str());
    if(rsa==NULL)
    {
        qDebug()<<ERR_reason_error_string(ERR_get_error());
        RSA_free(rsa);
        BIO_free(bpPublic);
        return -6;
    }
    if(RSA_verify(NID_md5,(const unsigned char*)digest.toStdString().c_str(),digest.length(),(const unsigned char*)signText,len,rsa)!=1)
    {
        qDebug()<<ERR_reason_error_string(ERR_get_error());
        RSA_free(rsa);
        BIO_free(bpPublic);
        return -7;
    }
    RSA_free(rsa);
    BIO_free(bpPublic);
    return 0;
}
/*
    int RSA_sign(int type, const unsigned char *m, unsigned int m_len,
unsigned char *sigret, unsigned int *siglen, RSA *rsa);

    int RSA_verify(int type, const unsigned char *m, unsigned int m_len,
unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
*/
///
/// \brief testFunction
/// \param datas
/// \return
/// -2 account load error
/// -1 account write error
///  0 normal
///
int testFunction(DataStruct &datas)
{
    if(readAccounts(datas.accounts)<0)
    {
        Account item;
        item.userName="admin2";
        item.passWord="1234";
        datas.accounts.append(item);
    }
    else
    {
        qDebug()<<datas.accounts[0].userName<<datas.accounts[0].passWord;
        qDebug()<<datas.accounts[1].userName<<datas.accounts[1].passWord;
    }
    qDebug()<<signKey("./key/private/private1.pem","aabaWW,aa2","./key/private/private2.pem");
    qDebug()<<verifySign("./key/public/public1.pem","aabaWW,aa2","./key/signatures/private2.ds");
    /*
    if(!generateAndSaveKey("aabaWW,aa2",3))
        return -1;
    qDebug()<<getRandomNum(16);
    qDebug()<<getMd5("Hello");
    qDebug()<<"isSecure:"<<endl<<getSecureLevel("admin1","aabaWW,aa2");
    if(writeAccounts(datas.accounts)<0)
        return -1;
    writeLog("This is a test log 1.");
    writeLog("This is a test log 2.");
    QString log;
    loadLog(log);
    qDebug()<<log;
    if(loadAuth(datas.enterKey)<0)
    {
        writeAuth("ThisIsPassWord");
    }
    qDebug()<<datas.enterKey;*/
    return 0;
}
