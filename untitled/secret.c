#include "secret.h"
#include "base64.h"

gpgme_error_t secret_encrypt_data(gpgme_ctx_t ctx, gpgme_key_t key, char* plain_data, char** cipher_data, size_t len_plain, size_t* len_cipher) {
    gpgme_error_t err;
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&cipher);
    if (err) return err;
    err = gpgme_data_new_from_mem(&plain, plain_data, len_plain, 1);
    if (err) return err;
    err = gpgme_data_set_flag(plain, "sensitive", "1");
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    gpgme_key_t rec[] = { key, NULL };
    err = gpgme_op_encrypt(ctx, rec, 0, plain, cipher);
    if (err) return err;
    gpgme_data_release(plain);
    *cipher_data = gpgme_data_release_and_get_mem(cipher, len_cipher);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_decrypt_data(gpgme_ctx_t ctx, char* cipher_data, char** plain_data, size_t len_cipher, size_t* len_plain) {
    gpgme_error_t err;
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&plain);
    if (err) return err;
    err = gpgme_data_new_from_mem(&cipher, cipher_data, len_cipher, 1);
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    err = gpgme_data_set_flag(plain, "sensitive", "1");
    if (err) return err;
    err = gpgme_op_decrypt(ctx, cipher, plain);
    if (err) return err;
    gpgme_data_release(cipher);
    *plain_data = gpgme_data_release_and_get_mem(plain, len_plain);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_new(gpgme_ctx_t ctx, gpgme_key_t key, char* buf, size_t size, secret_t* sect) {
    gpgme_error_t err;
    (*sect) = gcry_malloc_secure(sizeof(struct secret));
    (*sect)->dsize = gcry_malloc_secure(sizeof(size_t));
    (*sect)->esize = gcry_malloc_secure(sizeof(size_t));
    *((*sect)->dsize) = size;
    err = secret_encrypt_data(ctx, key, buf, &(*sect)->data, size, (*sect)->esize);
    if (err) return err;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_new_password(gpgme_ctx_t ctx, gpgme_key_t key, secret_t* sect) {
    gpgme_error_t err;
    char* buf = gcry_random_bytes_secure(SECRET_PASSWORD_LENGTH, GCRY_STRONG_RANDOM);
    char* buf_b64 = base64_encode(buf, SECRET_PASSWORD_LENGTH, NULL, 0);
    gcry_free(buf);
    err = secret_new(ctx, key, buf_b64, SECRET_PASSWORD_B64_LENGTH, sect);
    gcry_free(buf_b64);
    if (err) return err;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_reveal(gpgme_ctx_t ctx, secret_t sect, char** buffer, size_t* size) {
    gpgme_error_t err;
    err = secret_decrypt_data(ctx, sect->data, buffer, *(sect->esize), size);
    if (err) return err;
    if (*size != *(sect->dsize)) return GPG_ERR_USER_2;
    return GPG_ERR_NO_ERROR;
}

void secret_delete(secret_t sect) {
    gcry_free(sect->esize);
    gcry_free(sect->dsize);
    gpgme_free(sect->data);
    gcry_free(sect);
}
