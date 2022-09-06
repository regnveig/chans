#include "secret.h"

Secret::Secret(gpgme_ctx_t *Context, QByteArray *Data, gpgme_key_t *Key) {
    gpgme_data_t PlainData;
    this->DataLength = (size_t)Data->length();
    this->Error = gpgme_data_new_from_mem(&PlainData, *Data, Data->length(), 1);
    if (this->Error) return;
    this->Error = gpgme_data_set_flag(PlainData, "sensitive", "1");
    if (this->Error) return;
    gpgme_data_new(&this->EncryptedData);
    if (Key != nullptr) {
        gpgme_key_t Recipients[] = { *Key, NULL };
        this->Error = gpgme_op_encrypt(*Context, Recipients, gpgme_encrypt_flags_t(), PlainData, this->EncryptedData);
        if (this->Error) return;
    } else {
        this->Error = gpgme_op_encrypt(*Context, NULL, gpgme_encrypt_flags_t(), PlainData, this->EncryptedData);
        if (this->Error) return;
    }
    this->Error = gpgme_data_set_flag(this->EncryptedData, "sensitive", "1");
    if (this->Error) return;
    gpgme_data_release(PlainData);
}

Secret::Secret(gpgme_ctx_t *Context, gpgme_key_t *Key) {
    QUuid *BlockBuffer = new QUuid();
    QByteArray *Buffer = new QByteArray();
    for (auto It = 0; It < 6; It++) {
        *BlockBuffer = QUuid::createUuid();
        Buffer->append(BlockBuffer->toRfc4122());
    }
    *Buffer = Buffer->toBase64();
    Secret(Context, Buffer, Key);
    *BlockBuffer = QUuid::createUuid();
    delete BlockBuffer;
    Buffer->clear();
    delete Buffer;
}

void Secret::Reveal(gpgme_ctx_t *Context, QByteArray *Data) {
    gpgme_data_t PlainData;
    gpgme_data_new(&PlainData);
    this->Error =  gpgme_op_decrypt(*Context, this->EncryptedData, PlainData);
    if (this->Error) return;
    char *Buffer = gpgme_data_release_and_get_mem(PlainData, &this->DataLength);
    *Data = QByteArray(Buffer);
    gpgme_free(Buffer);
}

gpgme_error_t Secret::ShowError() {
    return this->Error;
}

Secret::~Secret() {
    gpgme_data_release(this->EncryptedData);
    this->DataLength = 0;
}
