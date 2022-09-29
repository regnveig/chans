#include <assert.h>
#include <gcrypt.h>
#include <gpgme.h>
#include <stdlib.h>
#include <stdio.h>
#include <search.h>
#include <time.h>
#include "base64.h"
#include "uuid.h"
#include "secret.h"

// -----=====| READY |=====-----

const char* KEYPARMS_0 = "<GnupgKeyParms format=\"internal\">\nKey-Type: default\nSubkey-Type: default\nName-Real: ChanS\nName-Email: ";
const char* KEYPARMS_1 = "@session.id\nName-Comment: Session Key\nPassphrase: ";
const char* KEYPARMS_2 = "\n</GnupgKeyParms>\n";
const char* SENSITIVE_FLAG = "sensitive";
const char* TEXT_TRUE = "1";
const char* NEWLINE = "\n";
const int INT_TRUE = 1;
const int INT_FALSE = 0;

const size_t KEYRING_SALT_SIZE = 512;
const int KEYRING_HASH_ALGO = GCRY_MD_SHA3_512;


gpgme_error_t compose_parms(char* keyid, char* password, char** parms) {
    gpgme_error_t err;
    gpgme_data_t query;
    err = gpgme_data_new(&query);
    if (err) return err;
    err = gpgme_data_set_flag(query, SENSITIVE_FLAG, TEXT_TRUE);
    if (err) return err;
    if (gpgme_data_write(query, KEYPARMS_0, strlen(KEYPARMS_0)) != strlen(KEYPARMS_0)) {
        gpgme_data_release(query);
        return GPG_ERR_USER_1;
    }
    if (gpgme_data_write(query, keyid, (UUID_STR_LEN - 1)) !=(UUID_STR_LEN - 1)) {
        gpgme_data_release(query);
        return GPG_ERR_USER_1;
    }
    if (gpgme_data_write(query, KEYPARMS_1, strlen(KEYPARMS_1)) != strlen(KEYPARMS_1)) {
        gpgme_data_release(query);
        return GPG_ERR_USER_1;
    }
    if (gpgme_data_write(query, password, SECRET_PASSWORD_B64_LENGTH) != SECRET_PASSWORD_B64_LENGTH) {
        gpgme_data_release(query);
        return GPG_ERR_USER_1;
    }
    if (gpgme_data_write(query, KEYPARMS_2, strlen(KEYPARMS_2)) != strlen(KEYPARMS_2)) {
        gpgme_data_release(query);
        return GPG_ERR_USER_1;
    }
    *parms = gpgme_data_release_and_get_mem(query, NULL);
    return GPG_ERR_NO_ERROR;
}





gcry_error_t set_keyring_hasher(gcry_md_hd_t *hd) {
    gcry_error_t err;
    err = gcry_md_open(hd, KEYRING_HASH_ALGO, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
    if (err) return err;
    void *salt = gcry_random_bytes_secure(KEYRING_SALT_SIZE, GCRY_STRONG_RANDOM);
    err = gcry_md_setkey(*hd, &salt, KEYRING_SALT_SIZE);
    if (err) return err;
    gcry_free(salt);
    return GPG_ERR_NO_ERROR;
}



// -----=====| TYPES |=====-----



struct keyring_record {
    gcry_mpi_t hash;
    secret_t data;
    struct keyring_record* left;
    struct keyring_record* right;
};

typedef struct keyring_record* keyring_record_t;

struct keyring {
    keyring_record_t root;
    gpgme_ctx_t ctx;
    gpgme_key_t key;
    gcry_md_hd_t hasher;
};

typedef struct keyring* keyring_t;

keyring_t kr;

int frps_are_equal(const char* fpr1, const char* fpr2) {
    int pos = 0;
    while (pos < 16) {
        if ((*(fpr1 + pos)) != (*(fpr2 + pos))) return 0;
        pos++;
    }
    return 1;
}

gpgme_error_t keyring_master_password(keyring_t kr, void** password) {
    gcry_md_write(kr->hasher, SENSITIVE_FLAG, strlen(SENSITIVE_FLAG));
    void* password_buf = gcry_md_read(kr->hasher, KEYRING_HASH_ALGO);
    size_t len = 0;
    gpgme_data_t buf;
    gpgme_error_t err = gpgme_data_new(&buf);
    if (err) return err;
    while (len <= SECRET_PASSWORD_LENGTH) {
        if (gpgme_data_write(buf, password_buf, gcry_md_get_algo_dlen(KEYRING_HASH_ALGO)) != gcry_md_get_algo_dlen(KEYRING_HASH_ALGO)) {
            gcry_md_reset(kr->hasher);
            gpgme_data_release(buf);
            return GPG_ERR_SYSTEM_ERROR;
        };
        len += gcry_md_get_algo_dlen(KEYRING_HASH_ALGO);
    }
    gcry_md_reset(kr->hasher);
    char* bpwd = gpgme_data_release_and_get_mem(buf, NULL);
    *password = base64_encode(bpwd, SECRET_PASSWORD_LENGTH, NULL, 0);
    gpgme_free(bpwd);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t ExtPasswordCallBack(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
    if (frps_are_equal(passphrase_info + 17, kr->key->fpr + 24)) {
        void* pwd;
        keyring_master_password(kr, &pwd);
        gpgme_io_writen(fd, pwd, SECRET_PASSWORD_B64_LENGTH);
        gcry_free(pwd);
        gpgme_io_writen(fd, NEWLINE, 1);
        return GPG_ERR_NO_ERROR;
    }
    return 1;
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
    gpgme_set_armor(*ctx, INT_FALSE);
    gpgme_set_offline(*ctx, INT_TRUE);
    gpgme_signers_clear(*ctx);
    gpgme_set_passphrase_cb(*ctx, ExtPasswordCallBack, NULL);
    gpgme_set_pinentry_mode(*ctx, GPGME_PINENTRY_MODE_LOOPBACK);
    return GPG_ERR_NO_ERROR;
}

// -----=====| SECRET |=====-----



// -----=====| KEYRING |=====-----



static int keyring_compare_hashes(keyring_record_t pa, keyring_record_t pb) {
    int comparison = gcry_mpi_cmp(pa->hash, pb->hash);
    if (comparison < 0) return -1;
    if (comparison > 0) return 1;
    return 0;
}

// -----=====| KEYRING RECORD |=====-----

gcry_error_t init_keyring_record(keyring_t kr, secret_t data, void *key, size_t size, keyring_record_t *rec) {
    gcry_error_t err;
    *rec = gcry_malloc_secure(sizeof(struct keyring_record));
    (*rec)->left = NULL;
    (*rec)->right = NULL;
    (*rec)->data = data;
    gcry_md_write(kr->hasher, key, size);
    unsigned char* hash = gcry_md_read(kr->hasher, KEYRING_HASH_ALGO);
    size_t nscanned;
    err = gcry_mpi_scan(&(*rec)->hash, GCRYMPI_FMT_USG, hash, gcry_md_get_algo_dlen(KEYRING_HASH_ALGO), &nscanned);
    gcry_md_reset(kr->hasher);
    if (err) return err;
    if (nscanned != gcry_md_get_algo_dlen(KEYRING_HASH_ALGO)) return GPG_ERR_USER_3;
    return GPG_ERR_NO_ERROR;
}

void delete_keyring_record(keyring_record_t rec) {
    gcry_mpi_release(rec->hash);
    gcry_free(rec);
}




gpgme_error_t keyring_generate_key(keyring_t kr, gpgme_key_t *key) {
    char* keyid;
    generate_uuid(&keyid);
    void* password_buf;
    keyring_master_password(kr, &password_buf);
    char* parms;
    compose_parms(keyid, password_buf, &parms);
    fprintf(stderr, "%s", parms);
    gpgme_op_genkey(kr->ctx, parms, NULL, NULL);
    gpgme_genkey_result_t res = gpgme_op_genkey_result(kr->ctx);
    gpgme_get_key(kr->ctx, res->fpr, key, 0);
    return 0;

}

int keyring_add(keyring_t kr, keyring_record_t rec, keyring_record_t* node) {
    if (!kr->root) {
        kr->root = rec;
        fprintf(stderr, "Root!");
        return 0;
    }
    if (!node) node = &(kr->root);
    int compare = keyring_compare_hashes(*node, rec);
    switch (compare) {
    case 1:
        if (!(*node)->left) {
            (*node)->left = rec;
            fprintf(stderr, "Go left!");
            return 0;
        } else return keyring_add(kr, rec, &(*node)->left);
    case -1:
        if (!(*node)->right) {
            (*node)->right = rec;
            fprintf(stderr, "Go right!");
            return 0;
        } else return keyring_add(kr, rec, &(*node)->right);
    default:
        fprintf(stderr, "Fuck!");
        return 1;
    }
}

int keyring_find(keyring_t kr, void *key, size_t size, secret_t* found, keyring_record_t* node) {
    if (!kr->root) return 1;
    if (!node) node = &(kr->root);
    keyring_record_t temp;
    init_keyring_record(kr, NULL, key, size, &temp);
    int compare = keyring_compare_hashes(*node, temp);
    delete_keyring_record(temp);
    switch (compare) {
    case 1:
        if (!(*node)->left) return 1;
        else return keyring_find(kr, key, size, found, &(*node)->left);
    case -1:
        if (!(*node)->right) return 1;
        else return keyring_find(kr, key, size, found, &(*node)->right);
    default:
        *found = (*node)->data;
        return 0;
    }
}

int keyring_init(keyring_t* kr) {
    *kr = gcry_malloc_secure(sizeof(struct keyring));
    (*kr)->root = NULL;
    gpgme_error_t cerr = set_keyring_context(&(*kr)->ctx);
    if (cerr) return 1;
    gpg_err_code_t gerr = set_keyring_hasher(&(*kr)->hasher);
    if (gerr) return 1;
    cerr = keyring_generate_key(*kr, &(*kr)->key);
    if (cerr) return 1;
    return 0;
}

int main()
{
    keyring_init(&kr);
    secret_t s;
    secret_new_password(kr->ctx, kr->key, &s);
    char* d;
    size_t w;
    secret_reveal(kr->ctx, s, &d, &w);
    fprintf(stderr, "%s\n", d);
    keyring_record_t r;
    keyring_record_t r2;
    char* key = "foo";
    char* key2 = "bar";
    init_keyring_record(kr, s, key, 3, &r);
    init_keyring_record(kr, s, key2, 3, &r2);
    keyring_add(kr, r, NULL);
    keyring_add(kr, r2, NULL);
    secret_t found;
    fprintf(stderr, "%d", keyring_find(kr, key2, 2, &found, NULL));
    return 0;
}
