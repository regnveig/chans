#include <gpgme.h>
#include <chunker.h>
#include <secret.h>
#include <keyring.h>
#include <QByteArrayView>
#include <QDataStream>
#include <QDebug>
#include <QException>
#include <QUuid>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <QtSql>
#include <gcrypt.h>

//Keyring MainKeyring = Keyring();
//    QByteArray fpr;

//gpgme_error_t ExtPasswordCallBack(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
 //   QByteArray sl;
  //  MainKeyring.GetSecret(&sl, &fpr);
   // qDebug() << sl;
//}

long Hook;

class GpgObject {
public:
    GpgObject(const char* Signer) {
        this->SetContext(Signer);
    }

    ~GpgObject() {
        gpgme_release(this->Context);
    }
    void GetPublicKey(const char* Fingerprint, QByteArray *Key) {
        gpgme_data_t Keydata;
        this->Error = gpgme_data_new(&Keydata);
        if (this->Error) return;
        gpgme_key_t KeyObject;
        this->Error = gpgme_get_key(this->Context, Fingerprint, &KeyObject, 0);
        if (this->Error) return;
        gpgme_key_t Keys[2] = { KeyObject, NULL };
        this->Error = gpgme_op_export_keys(this->Context, Keys, 0, Keydata);
        if (this->Error) return;
        QByteArray ArmoredKey = gpgme_data_release_and_get_mem(Keydata, 0);
        *Key = Secret::Dearmor(&ArmoredKey);
        gpgme_key_release(KeyObject);
    }
    void EncryptAndSign(const char* Fingerprint, QByteArray *Message, QByteArray *Cipher) {
        gpgme_data_t PlainData, CipherData;
        this->Error("1",   gpgme_data_new(&CipherData));
        this->Error("2",   gpgme_data_new_from_mem(&PlainData, Message->constData(), Message->length(), 1));
        gpgme_key_t KeyObject;
        this->Error("3",   gpgme_get_key(this->Context, Fingerprint, &KeyObject, 0));
        gpgme_key_t Keys[2] = { KeyObject, NULL };
        this->Error("4",   gpgme_op_encrypt_sign(this->Context, Keys, GPGME_ENCRYPT_ALWAYS_TRUST, PlainData, CipherData));
        QByteArray ArmoredCipher = gpgme_data_release_and_get_mem(CipherData, 0);
        *Cipher = Secret::Dearmor(&ArmoredCipher);
        gpgme_data_release(PlainData);
        gpgme_key_release(KeyObject);
    }

    void DecryptAndVerify(QByteArray *Cipher, QByteArray *Message, gpgme_signature_t *Signature) {
        gpgme_data_t PlainData, CipherData;
        this->Error("1",   gpgme_data_new(&PlainData));
        this->Error("2",   gpgme_data_new_from_mem(&CipherData, Cipher->constData(), Cipher->length(), 1));
        this->Error("3",   gpgme_op_decrypt_verify(this->Context, CipherData, PlainData));
        *Message = gpgme_data_release_and_get_mem(PlainData, 0);
        gpgme_verify_result_t Result = gpgme_op_verify_result(this->Context);
        *Signature = Result->signatures;
        gpgme_data_release(CipherData);
    }
private:
    gpgme_ctx_t Context;
    void Error(const char *stage, gpgme_error_t err) {
        if (err) throw std::runtime_error((QString(stage) + ": " + QString(gpgme_strerror(err))).toLocal8Bit());
    };



    void SetContext(const char* Signer) {
        gpgme_check_version(NULL);
        this->Error = gpgme_new(&this->Context);
        if (this->Error) return;
        const char* Engine = gpgme_get_dirinfo("gpg-name");
        const char* HomeDir = gpgme_get_dirinfo("homedir");
        this->Error = gpgme_ctx_set_engine_info(this->Context, GPGME_PROTOCOL_OPENPGP, Engine, HomeDir);
        if (this->Error) return;
        gpgme_set_armor(this->Context, 1);
        gpgme_set_offline(this->Context, 1);
        gpgme_signers_clear(this->Context);
        gpgme_key_t KeyObject;
        this->Error = gpgme_get_key(this->Context, Signer, &KeyObject, 0);
        if (this->Error) return;
        this->Error = gpgme_signers_add(this->Context, KeyObject);
        if (this->Error) return;
        //gpgme_set_passphrase_cb(this->Context, ExtPasswordCallBack, &Hook);
        //gpgme_set_pinentry_mode(this->Context, GPGME_PINENTRY_MODE_LOOPBACK);
    }




};

// -----=====| GPG END |=====-----

int main(int argc, char *argv[]) {
    char * buf;
    buf = (char*)gcry_random_bytes_secure(129, GCRY_STRONG_RANDOM);
    qDebug() << QByteArray(buf, 96).toBase64();
    return 0;
}
