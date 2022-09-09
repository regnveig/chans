#ifndef SECRET_H
#define SECRET_H

#include <QByteArray>
#include <QDebug>
#include <QUuid>
#include <gpgme.h>

class Secret {
public:
    Secret(gpgme_ctx_t *Context, QByteArray *Data, gpgme_key_t *Key);
    void Reveal(gpgme_ctx_t *Context, QByteArray *Data);
    gpgme_error_t ShowError();
    ~Secret();
    static QByteArray Dearmor(QByteArray *Message);
private:
    QByteArray *EncryptedData;
    size_t DataLength;
    gpgme_error_t Error = GPG_ERR_NO_ERROR;
    quint16 Stage = 0;
};

#endif // SECRET_H
