#include <assert.h>
#include <gcrypt.h>
#include <gpgme.h>
#include <stdlib.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <search.h>

struct secret_t {
    char* data;
    size_t esize, dsize;
};

struct keyring_record_t {
    gcry_mpi_t hash;
    struct secret_t *data;
};

struct keyring_t {
    void *table;
    gpgme_ctx_t ctx;
    gpgme_key_t key;
    gcry_md_hd_t hasher;
};

const size_t SECRET_PASSWORD_LENGTH = 96;
const size_t KEYRING_SALT_SIZE = 512;
const int KEYRING_HASH_ALGO = GCRY_MD_SHA3_512;

static int keyring_compare_hashes(const void *pa, const void *pb) {
    struct keyring_record_t *kpa = (struct keyring_record_t *)pa;
    struct keyring_record_t *kpb = (struct keyring_record_t *)pb;
    int comparison = gcry_mpi_cmp(kpa->hash, kpb->hash);
    if (comparison < 0) return -1;
    if (comparison > 0) return 1;
    return 0;
}

gcry_error_t init_keyring_record(struct keyring_t *kr, struct secret_t *data, void *key, size_t size, struct keyring_record_t **rec) {
    gcry_error_t err;
    *rec = gcry_malloc_secure(sizeof(struct keyring_record_t));
    (*rec)->data = data;
    gcry_md_write(kr->hasher, key, size);
    unsigned char *hash = gcry_md_read(kr->hasher, KEYRING_HASH_ALGO);
    size_t nscanned;
    err = gcry_mpi_scan(&(*rec)->hash, GCRYMPI_FMT_USG, hash, gcry_md_get_algo_dlen(KEYRING_HASH_ALGO), &nscanned);
    if (err) return err;
    assert(nscanned == gcry_md_get_algo_dlen(KEYRING_HASH_ALGO));
    gcry_free(hash);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_new_password(gpgme_ctx_t ctx, gpgme_key_t *key, struct secret_t **secret) {
    gpgme_error_t err;
    char *buf = gcry_random_bytes_secure(SECRET_PASSWORD_LENGTH, GCRY_STRONG_RANDOM);
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&cipher);
    if (err) return err;
    err = gpgme_data_new_from_mem(&plain, buf, SECRET_PASSWORD_LENGTH, 1);
    if (err) return err;
    gcry_free(buf);
    err = gpgme_data_set_flag(plain, "sensitive", "1");
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    gpgme_key_t rec[] = { *key, NULL };
    err = gpgme_op_encrypt(ctx, rec, GPGME_ENCRYPT_NO_COMPRESS, plain, cipher);
    if (err) return err;
    gpgme_data_release(plain);
    *secret = gcry_malloc_secure(sizeof(struct secret_t));
    (*secret)->data = gpgme_data_release_and_get_mem(cipher, &(*secret)->esize);
    (*secret)->dsize = SECRET_PASSWORD_LENGTH;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_new(gpgme_ctx_t ctx, gpgme_key_t *key, void **buffer, size_t size, struct secret_t **secret) {
    gpgme_error_t err;
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&cipher);
    if (err) return err;
    err = gpgme_data_new_from_mem(&plain, *buffer, size, 1);
    if (err) return err;
    err = gpgme_data_set_flag(plain, "sensitive", "1");
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    gpgme_key_t rec[] = { *key, NULL };
    err = gpgme_op_encrypt(ctx, rec, GPGME_ENCRYPT_NO_COMPRESS, plain, cipher);
    if (err) return err;
    gpgme_data_release(plain);
    *secret = gcry_malloc_secure(sizeof(struct secret_t));
    (*secret)->data = gpgme_data_release_and_get_mem(cipher, &(*secret)->esize);
    (*secret)->dsize = size;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_reveal(gpgme_ctx_t ctx, struct secret_t *secret, void **buffer, size_t *size) {
    gpgme_error_t err;
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&plain);
    if (err) return err;
    err = gpgme_data_new_from_mem(&cipher, secret->data, secret->esize, 1);
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    err = gpgme_data_set_flag(plain, "sensitive", "1");
    if (err) return err;
    err = gpgme_op_decrypt(ctx, cipher, plain);
    if (err) return err;
    gpgme_data_release(cipher);
    *buffer = gpgme_data_release_and_get_mem(plain, size);
    assert(*size == secret->dsize);
    return GPG_ERR_NO_ERROR;
}

void secret_delete(struct secret_t *secret) {
    gpgme_free(secret->data);
    secret->esize = 0;
    secret->dsize = 0;
    gcry_free(secret);
}

gpgme_error_t set_keyring_context(gpgme_ctx_t *ctx) {
    gpgme_error_t err;
    gpgme_check_version(NULL);
    err = gpgme_new(ctx);
    if (err) return err;
    const char *Engine = gpgme_get_dirinfo("gpg-name");
    const char *HomeDir = gpgme_get_dirinfo("homedir");
    err = gpgme_ctx_set_engine_info(*ctx, GPGME_PROTOCOL_OPENPGP, Engine, HomeDir);
    if (err) return err;
    gpgme_set_armor(*ctx, 0);
    gpgme_set_offline(*ctx, 1);
    gpgme_signers_clear(*ctx);
    return GPG_ERR_NO_ERROR;
}

gpg_err_code_t set_keyring_hasher(gcry_md_hd_t *hd) {
    gpg_err_code_t err;
    err = gcry_md_open(hd, KEYRING_HASH_ALGO, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
    if (err) return err;
    void *salt = gcry_random_bytes_secure(KEYRING_SALT_SIZE, GCRY_STRONG_RANDOM);
    err = gcry_md_setkey(*hd, &salt, KEYRING_SALT_SIZE);
    if (err) return err;
    gcry_free(salt);
    return GPG_ERR_NO_ERROR;
}

void generate_uuid(char** uuid) {
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    *uuid = gcry_malloc_secure(UUID_STR_LEN);
    uuid_unparse_lower(binuuid, *uuid);
}

int keyring_init(struct keyring_t** kr) {
    *kr = gcry_malloc_secure(sizeof(struct keyring_t));
    gpgme_error_t cerr;
    cerr = set_keyring_context(&(*kr)->ctx);
    if (cerr) return cerr;
    gpg_err_code_t gerr;
    gerr = set_keyring_hasher(&(*kr)->hasher);
    if (gerr) return gerr;
    return GPG_ERR_NO_ERROR;
}

void delete_keyring_record(struct keyring_record_t *rec) {
    gcry_mpi_release(rec->hash);
    secret_delete(rec->data);
    gcry_free(rec);
}

gcry_error_t keyring_find(struct keyring_t* kr, void *key, size_t size, struct secret_t **secret) {
    gcry_error_t err;
    struct keyring_record_t *buf;
    err = init_keyring_record(kr, NULL, key, size, &buf);
    if (err) return err;
    struct keyring_record_t *found = (struct keyring_record_t *)tfind(buf, &kr->table, keyring_compare_hashes);
    if (found != NULL) *secret = found->data;
    else *secret = NULL;
    return GPG_ERR_NO_ERROR;
}

int main()
{
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    err = set_keyring_context(&ctx);
    if (err) return err;
    //gpgme_key_t KeyObject;
    //err = gpgme_get_key(ctx, "4A4F1879F61BAE15699464DA0DF20F891BC61329", &KeyObject, 0);
    //if (err) return err;
    return 0;
}
