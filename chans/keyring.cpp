#include "keyring.h"

Keyring::Keyring() {
    this->Salt = new QByteArray();
    *this->Salt = QUuid::createUuid().toRfc4122();
    this->SetContext();
    if (this->Error) return;
    GenerateSessionKey(&this->MasterKey, nullptr);
    if (this->Error) return;
    QByteArray Fingerprint;
    QByteArray Pass;
    this->AddKey(&Fingerprint);
    this->GetSecret(&Pass, &Fingerprint);
    qDebug() << Pass;
    if (this->Error) return;
}

Keyring::~Keyring() {
    QMap<QByteArray, Secret*>::const_iterator It = this->Secrets.constBegin();
    while (It != this->Secrets.constEnd()) {
        delete this->Secrets[It.key()];
        this->Secrets.remove(It.key());
        ++It;
    }
    delete this->Salt;
    gpgme_key_release(this->MasterKey);
    gpgme_release(this->Context);
}

void Keyring::AddKey(QByteArray *Fingerprint) {
    gpgme_key_t NewKey;
    GenerateSessionKey(&NewKey, &this->MasterKey);
    if (this->Error) return;
    *Fingerprint = NewKey->fpr;
    *Fingerprint = Fingerprint->right(16);
    gpgme_key_release(NewKey);
}

void Keyring::AddSecret(QByteArray *SecretLine, QByteArray *Alias) {
    Secret *NewSecret = new Secret(&this->Context, SecretLine, &this->MasterKey);
    if (NewSecret->ShowError()) return;
    QByteArray *Hash = new QByteArray();
    *Hash = QCryptographicHash::hash(*Alias + *this->Salt, QCryptographicHash::Sha3_512);
    this->Secrets[QByteArray(*Hash)] = NewSecret;
}

void Keyring::GetSecret(QByteArray *SecretLine, QByteArray *Alias) {
    QByteArray *Hash = new QByteArray();
    *Hash = QCryptographicHash::hash(Alias->data() + *this->Salt, QCryptographicHash::Sha3_512);
    if (this->Secrets.contains(*Hash)) {
        this->Secrets[*Hash]->Reveal(&this->Context, SecretLine);
        if (this->Secrets[*Hash]->ShowError()) return;
    } else {
        this->Error = GPG_ERR_NO_KEY;
    }
    Hash->clear();
    delete Hash;
}

QByteArray Keyring::ShortenFpr(char *Fpr) { return QByteArray(Fpr).right(16); }

void Keyring::SetContext() {
    gpgme_check_version(NULL);
    this->Error = gpgme_new(&(this->Context));
    if (this->Error) return;
    const char *Engine = gpgme_get_dirinfo("gpg-name");
    const char *HomeDir = gpgme_get_dirinfo("homedir");
    this->Error = gpgme_ctx_set_engine_info(this->Context, GPGME_PROTOCOL_OPENPGP, Engine, HomeDir);
    if (this->Error) return;
    gpgme_set_armor(this->Context, 1);
    gpgme_set_offline(this->Context, 1);
    gpgme_signers_clear(this->Context);
}

void Keyring::GenerateSessionID(QByteArray *SessionID) {
    QUuid *Buffer = new QUuid();
    *Buffer = QUuid::createUuid();
    *SessionID = Buffer->toByteArray(QUuid::WithoutBraces);
    *Buffer = QUuid::createUuid();
    delete Buffer;
}

void Keyring::GenerateSessionKey(gpgme_key_t *NewKey, gpgme_key_t *Key) {
    QByteArray *SessionID = new QByteArray();
    GenerateSessionID(SessionID);
    QByteArray *Query = new QByteArray();
    Query->append("<GnupgKeyParms format=\"internal\">\n");
    Query->append("Key-Type: default\n");
    Query->append("Subkey-Type: default\n");
    Query->append("Name-Real: chans\n");
    Query->append("Name-Email: " + *SessionID + "@session.id\n");
    Query->append("Name-Comment: session key\n");
    SessionID->clear();
    delete SessionID;
    Secret *SessionPassword;
    if (Key != nullptr) {
        SessionPassword = new Secret(&this->Context, nullptr, Key);
        if (SessionPassword->ShowError()) return;
        QByteArray *TextPassword = new QByteArray();
        SessionPassword->Reveal(&this->Context, TextPassword);
        if (SessionPassword->ShowError()) return;
        Query->append("Passphrase: " + *TextPassword + "\n");
        TextPassword->clear();
        delete TextPassword;
    } else Query->append("%no-protection");
    Query->append("</GnupgKeyParms>\n");
    this->Error = gpgme_op_genkey(this->Context, *Query, NULL, NULL);
    Query->clear();
    delete Query;
    if (this->Error) return;
    gpgme_genkey_result_t Res = gpgme_op_genkey_result(this->Context);
    QByteArray *Hash = new QByteArray();
    *Hash = QCryptographicHash::hash(ShortenFpr(Res->fpr) + *this->Salt, QCryptographicHash::Sha3_512);
    if (Key != nullptr) this->Secrets[QByteArray(*Hash)] = SessionPassword;
    this->Error = gpgme_get_key(this->Context, Res->fpr, NewKey, 0);
    if (this->Error) return;
}
