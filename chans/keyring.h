#ifndef KEYRING_H
#define KEYRING_H

#include <QByteArray>
#include <QCryptographicHash>
#include <QDebug>
#include <QMap>
#include <gpgme.h>
#include <secret.h>

class Keyring {
public:
    Keyring();
    ~Keyring();
    void AddKey(QByteArray *Fingerprint);
    void AddSecret(QByteArray *SecretLine, QByteArray *Alias);
    void GetSecret(QByteArray *SecretLine, QByteArray *Alias);
private:
    QMap<QByteArray, Secret*> Secrets;
    gpgme_key_t MasterKey;
    QByteArray *Salt;
    gpgme_ctx_t Context;
    gpgme_error_t Error = GPG_ERR_NO_ERROR;
    QByteArray ShortenFpr(char *Fpr);
    void SetContext();
    void GenerateSessionID(QByteArray *SessionID);
    void GenerateSessionKey(gpgme_key_t *NewKey, gpgme_key_t *Key);
};

#endif // KEYRING_H
