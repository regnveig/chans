#include "secret.h"

Secret::Secret(gpgme_ctx_t *Context, QByteArray *Data, gpgme_key_t *Key) {
    this->EncryptedData = new QByteArray();
    QByteArray *InternalData = new QByteArray();
    if (Data == nullptr) {
        QUuid *BlockBuffer = new QUuid();
        QByteArray *Buffer = new QByteArray();
        for (auto It = 0; It < 6; It++) {
            *BlockBuffer = QUuid::createUuid();
            Buffer->append(BlockBuffer->toRfc4122());
        }
        *InternalData = Buffer->toBase64();
        *BlockBuffer = QUuid::createUuid();
        delete BlockBuffer;
        Buffer->clear();
        delete Buffer;
    } else {
        *InternalData = *Data;
    }
    *InternalData = InternalData->toBase64();
    gpgme_data_t PlainData;
    gpgme_data_t Encrypted;
    this->DataLength = (size_t)InternalData->length();
    this->Error = gpgme_data_new_from_mem(&PlainData, *InternalData, this->DataLength, 1);
    if (this->Error) { this->Stage = 1; return; }
    this->Error = gpgme_data_set_flag(PlainData, "sensitive", "1");
    if (this->Error) { this->Stage = 2; return; }
    this->Error = gpgme_data_set_encoding(PlainData, GPGME_DATA_ENCODING_BASE64);
    if (this->Error) { this->Stage = 3; return; }
    gpgme_data_new(&Encrypted);
    gpgme_key_t Recipients[] = { *Key, NULL };
    this->Error = gpgme_op_encrypt(*Context, Recipients, GPGME_ENCRYPT_NO_COMPRESS, PlainData, Encrypted);
    if (this->Error) { this->Stage = 4; return; }
    QByteArray Enc = gpgme_data_release_and_get_mem(Encrypted, 0);
    *this->EncryptedData = Secret::Dearmor(&Enc);
    gpgme_data_release(PlainData);
    InternalData->clear();
    delete InternalData;
}

void Secret::Reveal(gpgme_ctx_t *Context, QByteArray *Data) {
    gpgme_data_t Encrypted;
    this->Error = gpgme_data_new_from_mem(&Encrypted, *this->EncryptedData, this->EncryptedData->length(), 1);
    if (this->Error) { this->Stage = 5; return; }
    gpgme_data_t PlainData;
    gpgme_data_new(&PlainData);
    this->Error = gpgme_op_decrypt(*Context, Encrypted, PlainData);
    if (this->Error) { this->Stage = 6; return; }
    gpgme_data_release(Encrypted);
    this->Error = gpgme_data_set_encoding(PlainData, GPGME_DATA_ENCODING_BASE64);
    if (this->Error) { this->Stage = 7; return; }
    char *Buffer = gpgme_data_release_and_get_mem(PlainData, &this->DataLength);
    // BUG: gpgme_data_release_and_get_mem returns some technical info of gpg, so I have to cut output up to expected length.
    *Data = QByteArray(Buffer);
    gpgme_free(Buffer);
    *Data = Data->left(this->DataLength);
    *Data = QByteArray::fromBase64(*Data);
}

gpgme_error_t Secret::ShowError() { return this->Error; }

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
