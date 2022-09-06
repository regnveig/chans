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

// -----=====| GPG BEGIN |=====-----

// Used: 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112

long Hook;

class GpgObject {
public:
    GpgObject(const char* Signer) {
        this->SetContext(Signer);
        this->Keys = new Keyring(&this->Context);
    }

    ~GpgObject() {
        delete this->Keys;
        gpgme_release(this->Context);
    }



    gpgme_error_t PasswordCallBack(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
        qDebug() << (long)hook;
        qDebug() << uid_hint;
        QByteArray PI = passphrase_info;
        if (PI.length() != 0) {
            QByteArray Fpt = PI.split(' ')[1];
        } else {
            qDebug() << "hohoho";
            const char * nl = "\n";
            QTextStream qtin(stdin);
            const char * pass = qtin.readLine().toLocal8Bit();
            gpgme_io_writen(fd, pass, strlen(pass));
            gpgme_io_writen(fd, nl, 1);
        }
        qDebug() << prev_was_bad;
        qDebug() << fd;

        return GPG_ERR_CANCELED;
    }
private:
    gpgme_ctx_t Context;
    gpgme_error_t Error;
    Keyring *Keys;

    QByteArray Dearmor(QByteArray* Message) {
        // GPGME fails to work not in armor mode :c
        QList List = (*Message).split('\n');
        List = List.mid(2, List.length() - 5);
        return QByteArray::fromBase64(List.join());
    }

    gpgme_error_t GetPublicKey(gpgme_ctx_t* Context, const char* Fingerprint, QByteArray *Key) {
        gpgme_error_t Error;
        gpgme_data_t Keydata;
        Error = gpgme_data_new(&Keydata);
        if (Error) return Error;
        gpgme_key_t KeyObject;
        Error = gpgme_get_key (*Context, Fingerprint, &KeyObject, 0);
        if (Error) return Error;
        gpgme_key_t Keys[2] = { KeyObject, NULL };
        Error = gpgme_op_export_keys(*Context, Keys, 0, Keydata);
        if (Error) return Error;
        QByteArray ArmoredKey = gpgme_data_release_and_get_mem(Keydata, 0);
        *Key = ""; //DearmorGPG(&ArmoredKey);
        gpgme_key_release(KeyObject);
        return GPG_ERR_NO_ERROR;
    }

    void SetContext(const char* Signer) {
        gpgme_check_version(NULL);
        this->Error = gpgme_new(&(this->Context));
        if (this->Error) { this->ExplainError(108); return; }
        const char* Engine = gpgme_get_dirinfo("gpg-name");
        const char* HomeDir = gpgme_get_dirinfo("homedir");
        this->Error = gpgme_ctx_set_engine_info(this->Context, GPGME_PROTOCOL_OPENPGP, Engine, HomeDir);
        if (this->Error) { this->ExplainError(109); return; }
        gpgme_set_armor(this->Context, 1);
        gpgme_set_offline(this->Context, 1);
        gpgme_signers_clear(this->Context);
        gpgme_key_t KeyObject;
        this->Error = gpgme_get_key(this->Context, Signer, &KeyObject, 0);
        if (this->Error) { this->ExplainError(110); return; }
        this->Error = gpgme_signers_add(this->Context, KeyObject);
        if (this->Error) { this->ExplainError(111); return; }
        gpgme_passphrase_cb_t pcb = ExtPasswordCallBack;
        gpgme_set_passphrase_cb(this->Context, pcb, &Hook);
        gpgme_set_pinentry_mode(this->Context, GPGME_PINENTRY_MODE_LOOPBACK );
    }

    void ExplainError(quint16 Operation) {
        const char * ErrorExplanation = gpgme_strerror(this->Error);
        qDebug() << "[ERROR] GPGME Error:" << this->Error << ErrorExplanation << "|" << "Operation:" << Operation;
    }
    void EncryptAndSign(const char* Fingerprint, QByteArray *Message, QByteArray *Cipher) {
        gpgme_data_t PlainData;
        gpgme_data_t CipherData;
        this->Error = gpgme_data_new(&CipherData);
        if (this->Error) { this->ExplainError(106); return; }
        this->Error = gpgme_data_new_from_mem(&PlainData, (*Message).constData(), (*Message).length(), 1);
        if (this->Error) { this->ExplainError(106); return; }
        gpgme_key_t KeyObject;
        this->Error = gpgme_get_key(this->Context, Fingerprint, &KeyObject, 0);
        if (this->Error) { this->ExplainError(106); return; }
        gpgme_key_t Keys[2] = { KeyObject, NULL };
        this->Error = gpgme_op_encrypt_sign(this->Context, Keys, GPGME_ENCRYPT_ALWAYS_TRUST, PlainData, CipherData);
        if (this->Error) { this->ExplainError(106); return; }
        QByteArray ArmoredCipher = gpgme_data_release_and_get_mem(CipherData, 0);
        *Cipher = Dearmor(&ArmoredCipher);
        gpgme_data_release(PlainData);
        gpgme_key_release(KeyObject);
    }

    void DecryptAndVerify(QByteArray *Cipher, QByteArray *Message, gpgme_signature_t *Signature) {
        gpgme_data_t PlainData;
        gpgme_data_t CipherData;
        this->Error = gpgme_data_new(&PlainData);
        if (this->Error) { this->ExplainError(106); return; }
        this->Error = gpgme_data_new_from_mem(&CipherData, (*Cipher).constData(), (*Cipher).length(), 1);
        if (this->Error) { this->ExplainError(106); return; }
        this->Error = gpgme_op_decrypt_verify(this->Context, CipherData, PlainData);
        if (this->Error) { this->ExplainError(106); return; }
        *Message = gpgme_data_release_and_get_mem(PlainData, 0);
        if (this->Error) { this->ExplainError(106); return; }
        gpgme_verify_result_t Result = gpgme_op_verify_result(this->Context);
        *Signature = Result->signatures;
        gpgme_data_release(CipherData);
    }


};

GpgObject *k;

gpgme_error_t ExtPasswordCallBack(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
    return k->PasswordCallBack(hook, uid_hint, passphrase_info, prev_was_bad, fd);
}

k = new GpgObject("A1662AA073AE46CD6FE88CDB8D12EDFB66827FA2");


// -----=====| GPG END |=====-----

int main(int argc, char *argv[])
{
    return 0;
}
