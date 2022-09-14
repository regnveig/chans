#include <assert.h>
#include <gcrypt.h>
#include <gpgme.h>
#include <stdlib.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <search.h>
#include <time.h>

void* hook;

// -----=====| CONST |=====-----

const size_t SECRET_PASSWORD_LENGTH = 96;
const size_t KEYRING_SALT_SIZE = 512;
const int KEYRING_HASH_ALGO = GCRY_MD_SHA3_512;
const int DEBUG_MODE = 1;

// -----=====| TYPES |=====-----

enum error_source {
    ERROR_FROM_CHANS = 0,
    ERROR_FROM_GPGME,
    ERROR_FROM_GCRY
};

struct chans_error {
    int error_code;
    enum error_source source;
    int stage;
};

struct secret {
    char* data;
    size_t esize, dsize;
};

typedef struct secret* secret_t;

struct keyring_record {
    gcry_mpi_t hash;
    secret_t data;
};

typedef struct keyring_record* keyring_record_t;

struct keyring {
    void* table;
    gpgme_ctx_t ctx;
    gpgme_key_t key;
    gcry_md_hd_t hasher;
};

typedef struct keyring* keyring_t;

// -----=====| UUID |=====-----

void generate_uuid(char** uuid) {
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    *uuid = gcry_malloc_secure(UUID_STR_LEN);
    uuid_unparse_lower(binuuid, *uuid);
}

void debug(const char *message) {
    if (DEBUG_MODE) printf("[DEBUG] %s\n", message);
}

gpgme_error_t password_cb(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd) {
    debug(passphrase_info);
    return 1;
}

// -----=====| BASE64 |=====-----

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * Source: http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
 */

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void* base64_encode(void *src, size_t len, size_t *out_len, int sep) {
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;
	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len) return NULL; /* integer overflow */
	out = gcry_malloc_secure(olen);
	if (out == NULL) return NULL;
	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
            if (sep) *pos++ = '\n';
			line_len = 0;
		}
	}
	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}
    if (line_len) { if (sep) *pos++ = sep; }
	*pos = '\0';
	if (out_len) *out_len = pos - out;
	return out;
}

// -----=====| SECRET |=====-----

gpgme_error_t secret_new_password(keyring_t kr, secret_t *ksecret) {
    if (!kr->key) {
        *ksecret = NULL;
        return GPG_ERR_NO_ERROR;
    }
    gpgme_error_t err;
    char *buf;
    buf = gcry_random_bytes_secure(SECRET_PASSWORD_LENGTH, GCRY_STRONG_RANDOM);
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
    gpgme_key_t rec[] = { kr->key, NULL };
    err = gpgme_op_encrypt(kr->ctx, rec, GPGME_ENCRYPT_NO_COMPRESS, plain, cipher);
    if (err) return err;
    gpgme_data_release(plain);
    *ksecret = gcry_malloc_secure(sizeof(struct secret));
    (*ksecret)->data = gpgme_data_release_and_get_mem(cipher, &(*ksecret)->esize);
    (*ksecret)->dsize = SECRET_PASSWORD_LENGTH;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_new(keyring_t kr, void **buffer, size_t size, secret_t *ksecret) {
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
    gpgme_key_t rec[] = { kr->key, NULL };
    err = gpgme_op_encrypt(kr->ctx, rec, GPGME_ENCRYPT_NO_COMPRESS, plain, cipher);
    if (err) return err;
    gpgme_data_release(plain);
    *ksecret = gcry_malloc_secure(sizeof(struct secret));
    (*ksecret)->data = gpgme_data_release_and_get_mem(cipher, &(*ksecret)->esize);
    (*ksecret)->dsize = size;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_reveal(keyring_t kr, secret_t secret, void **buffer, size_t *size) {
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
    err = gpgme_op_decrypt(kr->ctx, cipher, plain);
    if (err) return err;
    gpgme_data_release(cipher);
    *buffer = gpgme_data_release_and_get_mem(plain, size);
    assert(*size == secret->dsize);
    return GPG_ERR_NO_ERROR;
}

void secret_delete(secret_t ksecret) {
    if (ksecret) {
        if (ksecret->data) gpgme_free(ksecret->data);
        ksecret->esize = 0;
        ksecret->dsize = 0;
        gcry_free(ksecret);
    }
}

// -----=====| KEYRING |=====-----

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
    gpgme_set_passphrase_cb(*ctx, password_cb, hook);
    gpgme_set_pinentry_mode(*ctx, GPGME_PINENTRY_MODE_LOOPBACK);
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

static int keyring_compare_hashes(const void *pa, const void *pb) {
    keyring_record_t kpa = (keyring_record_t)pa;
    keyring_record_t kpb = (keyring_record_t)pb;
    int comparison = gcry_mpi_cmp(kpa->hash, kpb->hash);
    if (comparison < 0) return -1;
    if (comparison > 0) return 1;
    return 0;
}

// -----=====| KEYRING RECORD |=====-----

gcry_error_t init_keyring_record(keyring_t kr, secret_t data, void *key, size_t size, keyring_record_t *rec) {
    gcry_error_t err;
    *rec = gcry_malloc_secure(sizeof(struct keyring_record));
    (*rec)->data = data;
    gcry_md_write(kr->hasher, key, size);
    unsigned char *hash = gcry_md_read(kr->hasher, KEYRING_HASH_ALGO);
    gcry_md_reset(kr->hasher);
    size_t nscanned;
    err = gcry_mpi_scan(&(*rec)->hash, GCRYMPI_FMT_USG, hash, gcry_md_get_algo_dlen(KEYRING_HASH_ALGO), &nscanned);
    if (err) return err;
    assert(nscanned == gcry_md_get_algo_dlen(KEYRING_HASH_ALGO));
    return GPG_ERR_NO_ERROR;
}

void delete_keyring_record(keyring_record_t rec) {
    gcry_mpi_release(rec->hash);
    secret_delete(rec->data);
    gcry_free(rec);
}

// -----=====| KEYRING MANIP |=====-----

gcry_error_t keyring_find(keyring_t kr, void *key, size_t size, secret_t *ksecret) {
    gcry_error_t err;
    keyring_record_t buf;
    err = init_keyring_record(kr, NULL, key, size, &buf);
    if (err) return err;
    keyring_record_t found = tfind(buf, &kr->table, keyring_compare_hashes);
    if (found) *ksecret = found->data;
    else *ksecret = NULL;
    return GPG_ERR_NO_ERROR;
}

gcry_error_t keyring_add(keyring_t kr, void *key, size_t size, secret_t ksecret) {
    gcry_error_t err;
    secret_t test;
    err = keyring_find(kr, key, size, &test);
    if (err) return err;
    if (test) {
        secret_delete(test);
        return GPG_ERR_EALREADY;
    }
    keyring_record_t buf;
    err = init_keyring_record(kr, ksecret, key, size, &buf);
    if (err) return err;
    tsearch(buf, &kr->table, keyring_compare_hashes);
    return GPG_ERR_NO_ERROR;

}

int keyring_master_password(keyring_t kr, void** password) {
    int err;
    gcry_md_write(kr->hasher, "password", 8);
    void* password_buf = gcry_md_read(kr->hasher, KEYRING_HASH_ALGO);
    gcry_md_reset(kr->hasher);
    size_t len = 0;
    gpgme_data_t buf;
    err = gpgme_data_new(&buf);
    if (err) return err;
    while (len <= SECRET_PASSWORD_LENGTH) {
        assert(gpgme_data_write(buf, password_buf, gcry_md_get_algo_dlen(KEYRING_HASH_ALGO)) == gcry_md_get_algo_dlen(KEYRING_HASH_ALGO));
        len += gcry_md_get_algo_dlen(KEYRING_HASH_ALGO);
    }
    *password = gpgme_data_release_and_get_mem(buf, NULL);
    return 0;
}

int keyring_generate_key(keyring_t kr, gpgme_key_t *key) {
    char* keyid;
    int err;
    generate_uuid(&keyid);
    debug(keyid);

    gpgme_data_t query;
    err = gpgme_data_new(&query);
     if (err) return err;
    err = gpgme_data_set_flag(query, "sensitive", "1");
    if (err) return err;
    size_t data_size = 102;
    assert(gpgme_data_write(query, "<GnupgKeyParms format=\"internal\">\nKey-Type: default\nSubkey-Type: default\nName-Real: ChanS\nName-Email: ", data_size) == data_size);
    assert(gpgme_data_write(query, keyid, UUID_STR_LEN - 1) == UUID_STR_LEN - 1);
    gcry_free(keyid);
    data_size = 50;
    assert(gpgme_data_write(query, "@session.id\nName-Comment: Session Key\nPassphrase: ", data_size) == data_size);
    secret_t password;
    secret_new_password(kr, &password);

    void* password_buf;
    if (password == NULL) keyring_master_password(kr, &password_buf);
    else secret_reveal(kr, password, &password_buf, NULL);

    size_t pb64_len = 0;
    void* password_b64 = base64_encode(password_buf, SECRET_PASSWORD_LENGTH, &pb64_len, 0);
    assert(gpgme_data_write(query, password_b64, pb64_len) == pb64_len);
    gcry_free(password_b64);
    data_size = 18;
    assert(gpgme_data_write(query, "\n</GnupgKeyParms>\n", data_size) == data_size);
    size_t query_size;
    char* parms = gpgme_data_release_and_get_mem(query, &query_size);
    err = gpgme_op_genkey(kr->ctx, parms, NULL, NULL);
    if (err) return err;
    gpgme_free(parms);
    gpgme_genkey_result_t res = gpgme_op_genkey_result(kr->ctx);
    keyring_add(kr, res->fpr, 40, password);
    gpgme_get_key(kr->ctx, res->fpr, key, 0);
    return 0;

}
int keyring_init(keyring_t* kr) {
    *kr = gcry_malloc_secure(sizeof(struct keyring));
    gpgme_error_t cerr;
    cerr = set_keyring_context(&(*kr)->ctx);
    if (cerr) return cerr;
    gpg_err_code_t gerr;
    gerr = set_keyring_hasher(&(*kr)->hasher);
    if (gerr) return gerr;
    (*kr)->key = NULL;
    keyring_generate_key(*kr, &(*kr)->key);
    return GPG_ERR_NO_ERROR;
}
int main()
{
    debug("Start");
    keyring_t kr;
    int err = keyring_init(&kr);
    gpgme_key_t f;
    keyring_generate_key(kr, f);
    //if (err) return err;
    return 0;
}
