#ifndef KEYRING_H
#define KEYRING_H

#include <QByteArray>
#include <QMap>
#include <gpgme.h>
#include <secret.h>

class Keyring {
public:
    Keyring(gpgme_ctx_t *Context);
    ~Keyring();
    void NewKey(gpgme_ctx_t *Context, QByteArray *Fingerprint);
    void GetPass(gpgme_ctx_t *Context, QByteArray *Password, QByteArray *Fingerprint);
    void RemoveKey(QByteArray Fingerprint);
private:
    QMap<QByteArray, Secret*> Keys;
    gpgme_key_t MasterKey;
    QByteArray Database;
    gpgme_error_t Error = GPG_ERR_NO_ERROR;
    QByteArray ShortenFpr(char *Fpr);
    void GenerateSessionID(QByteArray *SessionID);
    void GenerateSessionKey(gpgme_ctx_t *Context, gpgme_key_t *NewKey, gpgme_key_t *Key);
};

#endif // KEYRING_H
