#include "keyring.h"

Keyring::Keyring(gpgme_ctx_t *Context) {
    GenerateSessionKey(Context, &this->MasterKey, nullptr);
}

Keyring::~Keyring() {
    QMap<QByteArray, Secret*>::const_iterator It = this->Keys.constBegin();
    while (It != this->Keys.constEnd()) {
        this->RemoveKey(It.key());
        ++It;
    }
    delete this->MasterKey;
}

void Keyring::NewKey(gpgme_ctx_t *Context, QByteArray *Fingerprint) {
    gpgme_key_t NewKey;
    GenerateSessionKey(Context, &NewKey, &this->MasterKey);
    *Fingerprint = QByteArray(NewKey->fpr).right(16);
    gpgme_key_release(NewKey);
}

void Keyring::GetPass(gpgme_ctx_t *Context, QByteArray *Password, QByteArray *Fingerprint) {
    QByteArray *ShortFpr = new QByteArray();
    *ShortFpr = ShortenFpr(Fingerprint->data());
    if (this->Keys.contains(*ShortFpr)) {
        this->Keys[*ShortFpr]->Reveal(Context, Password);
    } else {
        this->Error = GPG_ERR_NO_KEY;
    }
    ShortFpr->clear();
    delete ShortFpr;
}

void Keyring::RemoveKey(QByteArray Fingerprint) {
    QByteArray *ShortFpr = new QByteArray;
    *ShortFpr = ShortenFpr(Fingerprint.data());
    if (this->Keys.contains(*ShortFpr)) {
        delete this->Keys[*ShortFpr];
        this->Keys.remove(*ShortFpr);
    } else {
        this->Error = GPG_ERR_NO_KEY;
    }
    ShortFpr->clear();
    delete ShortFpr;
}

QByteArray Keyring::ShortenFpr(char * Fpr) { return QByteArray(Fpr).right(16); }

void Keyring::GenerateSessionID(QByteArray *SessionID) {
    QUuid *Buffer = new QUuid();
    *Buffer = QUuid::createUuid();
    *SessionID = Buffer->toByteArray(QUuid::WithoutBraces);
    *Buffer = QUuid::createUuid();
    delete Buffer;
}

void Keyring::GenerateSessionKey(gpgme_ctx_t *Context, gpgme_key_t *NewKey, gpgme_key_t *Key) {
    QByteArray *SessionID = new QByteArray();
    GenerateSessionID(SessionID);
    Secret *SessionPassword = new Secret(Context, Key);
    QByteArray *Query = new QByteArray();
    Query->append("<GnupgKeyParms format=\"internal\">\n");
    Query->append("Key-Type: default\n");
    Query->append("Subkey-Type: default\n");
    Query->append("Name-Real: chans\n");
    Query->append("Name-Email: " + *SessionID + "@session.id\n");
    SessionID->clear();
    delete SessionID;
    Query->append("Name-Comment: session key\n");
    QByteArray *TextPassword = new QByteArray();
    SessionPassword->Reveal(Context, TextPassword);
    Query->append("Passphrase: " + *TextPassword + "\n");
    TextPassword->clear();
    delete TextPassword;
    Query->append("</GnupgKeyParms>\n");
    this->Error = gpgme_op_genkey(*Context, *Query, NULL, NULL);
    if (this->Error) return;
    Query->clear();
    delete Query;
    gpgme_genkey_result_t Res = gpgme_op_genkey_result(*Context);
    this->Keys[ShortenFpr(Res->fpr)] = SessionPassword;
    this->Error = gpgme_get_key(*Context, Res->fpr, NewKey, 0);
    if (this->Error) return;
    this->Error = gpgme_op_keysign(*Context, *NewKey, (*NewKey)->uids->uid, 0, GPGME_KEYSIGN_NOEXPIRE);
    if (this->Error) return;
}
