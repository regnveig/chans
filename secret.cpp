#include "secret.h"

void Secret::Error(int Stage, gpgme_error_t Errno) {
    if (Errno) throw std::runtime_error("Secret.Error " + std::to_string(Stage) + ": " + gpgme_strerror(Errno));
};

Secret::Secret(gpgme_ctx_t *Context, QByteArray *Data, gpgme_key_t *Key) {


    this->EncryptedData = new QByteArray();
    QByteArray *InternalData = new QByteArray();
    if (Data == nullptr) {
        char *Buffer = (char*)gcry_random_bytes_secure(96, GCRY_STRONG_RANDOM);
        *InternalData = QByteArray(Buffer, 96);
    } else {
        *InternalData = *Data;
    }
    *InternalData = InternalData->toBase64();
    gpgme_data_t PlainData, Encrypted;
    this->Error(10, gpgme_data_new(&Encrypted));
    this->DataLength = (size_t)InternalData->length();
    this->Error(11, gpgme_data_new_from_mem(&PlainData, *InternalData, this->DataLength, 1));
    this->Error(12, gpgme_data_set_flag(PlainData, "sensitive", "1"));
    this->Error(13, gpgme_data_set_encoding(PlainData, GPGME_DATA_ENCODING_BASE64));
    gpgme_key_t Recipients[] = { *Key, NULL };
    this->Error(14, gpgme_op_encrypt(*Context, Recipients, GPGME_ENCRYPT_NO_COMPRESS, PlainData, Encrypted));
    QByteArray Enc = gpgme_data_release_and_get_mem(Encrypted, 0);
    *this->EncryptedData = Secret::Dearmor(&Enc);
    gpgme_data_release(PlainData);
    InternalData->clear();
    delete InternalData;
}

void Secret::Reveal(gpgme_ctx_t *Context, QByteArray *Data) {
    gpgme_data_t Encrypted;
    this->Error(15, gpgme_data_new_from_mem(&Encrypted, *this->EncryptedData, this->EncryptedData->length(), 1));
    gpgme_data_t PlainData;
    gpgme_data_new(&PlainData);
    this->Error(16, gpgme_op_decrypt(*Context, Encrypted, PlainData));
    gpgme_data_release(Encrypted);
    this->Error(17, gpgme_data_set_encoding(PlainData, GPGME_DATA_ENCODING_BASE64));
    char *Buffer = gpgme_data_release_and_get_mem(PlainData, &this->DataLength);
    // BUG: gpgme_data_release_and_get_mem returns some technical info of gpg, so I have to cut output up to expected length.
    *Data = QByteArray(Buffer);
    gpgme_free(Buffer);
    *Data = Data->left(this->DataLength);
    *Data = QByteArray::fromBase64(*Data);
}

Secret::~Secret() {
    this->EncryptedData->clear();
    delete this->EncryptedData;
    this->DataLength = 0;
}

QByteArray Secret::Dearmor(QByteArray *Message) {
    // BUG: GPGME fails to work not in armor mode.
    QList List = Message->split('\n');
    List = List.mid(2, List.length() - 5);
    QByteArray Result = List.join();
    List.clear();
    Result = QByteArray::fromBase64(Result);
    return Result;
}
