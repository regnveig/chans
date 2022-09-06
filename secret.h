#ifndef SECRET_H
#define SECRET_H

#include <QByteArray>
#include <QUuid>
#include <gpgme.h>

class Secret {
public:
    Secret(gpgme_ctx_t *Context, QByteArray *Data, gpgme_key_t *Key);
    Secret(gpgme_ctx_t *Context, gpgme_key_t *Key);
    void Reveal(gpgme_ctx_t *Context, QByteArray *Data);
    gpgme_error_t ShowError();
    ~Secret();
private:
    gpgme_data_t EncryptedData;
    size_t DataLength;
    gpgme_error_t Error = GPG_ERR_NO_ERROR;
};

#endif // SECRET_H
