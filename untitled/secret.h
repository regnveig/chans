#ifndef SECRET_H
#define SECRET_H

#include <gcrypt.h>
#include <gpgme.h>
#include <stddef.h>

static const size_t SECRET_PASSWORD_LENGTH = 96;
static const size_t SECRET_PASSWORD_B64_LENGTH = 128;

struct secret {
    char* data;
    size_t* esize;
    size_t* dsize;
};

typedef struct secret* secret_t;

gpgme_error_t secret_encrypt_data(gpgme_ctx_t ctx, gpgme_key_t key, char* plain_data, char** cipher_data, size_t len_plain, size_t* len_cipher);
gpgme_error_t secret_decrypt_data(gpgme_ctx_t ctx, char* cipher_data, char** plain_data, size_t len_cipher, size_t* len_plain);
gpgme_error_t secret_new(gpgme_ctx_t ctx, gpgme_key_t key, char* buf, size_t size, secret_t* sect);
gpgme_error_t secret_new_password(gpgme_ctx_t ctx, gpgme_key_t key, secret_t* sect);
gpgme_error_t secret_reveal(gpgme_ctx_t ctx, secret_t sect, char** buffer, size_t* size);
void secret_delete(secret_t sect);

#endif // SECRET_H
