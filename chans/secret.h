#ifndef SECRET_H
#define SECRET_H

#include <QByteArray>
#include <QDebug>
#include <gpgme.h>
#include <gcrypt.h>

class Secret {
public:
    Secret(gpgme_ctx_t *Context, QByteArray *Data, gpgme_key_t *Key);
    ~Secret();
    void Reveal(gpgme_ctx_t *Context, QByteArray *Data);
    static QByteArray Dearmor(QByteArray *Message);
private:
    QByteArray *EncryptedData;
    size_t *DataLength;
    void Error(int Stage, gpgme_error_t Errno);

};

#endif // SECRET_H
