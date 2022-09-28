#include <assert.h>
#include <gcrypt.h>
#include <gpgme.h>
#include <stdlib.h>
#include <stdio.h>
#include <uuid/uuid.h>
#include <search.h>
#include <time.h>

// -----=====| READY |=====-----

const char* KEYPARMS_0 = "<GnupgKeyParms format=\"internal\">\nKey-Type: default\nSubkey-Type: default\nName-Real: ChanS\nName-Email: ";
const char* KEYPARMS_1 = "@session.id\nName-Comment: Session Key\nPassphrase: ";
const char* KEYPARMS_2 = "\n</GnupgKeyParms>\n";
const char* SENSITIVE_FLAG = "sensitive";
const char* TEXT_TRUE = "1";
const int INT_TRUE = 1;
const int INT_FALSE = 0;
const size_t SECRET_PASSWORD_LENGTH = 96;
const size_t SECRET_PASSWORD_B64_LENGTH = 128;
const size_t KEYRING_SALT_SIZE = 512;
const int KEYRING_HASH_ALGO = GCRY_MD_SHA3_512;

void generate_uuid(char** uuid) {
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    *uuid = gcry_malloc_secure(UUID_STR_LEN);
    uuid_unparse_lower(binuuid, *uuid);
}

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

gpgme_error_t encrypt_data(gpgme_ctx_t ctx, gpgme_key_t key, char* plain_data, char** cipher_data, size_t len_plain, size_t* len_cipher) {
    gpgme_error_t err;
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&cipher);
    if (err) return err;
    err = gpgme_data_new_from_mem(&plain, plain_data, len_plain, INT_TRUE);
    if (err) return err;
    err = gpgme_data_set_flag(plain, SENSITIVE_FLAG, TEXT_TRUE);
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    gpgme_key_t rec[] = { key, NULL };
    err = gpgme_op_encrypt(ctx, rec, INT_FALSE, plain, cipher);
    if (err) return err;
    gpgme_data_release(plain);
    *cipher_data = gpgme_data_release_and_get_mem(cipher, len_cipher);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t decrypt_data(gpgme_ctx_t ctx, char* cipher_data, char** plain_data, size_t len_cipher, size_t* len_plain) {
    gpgme_error_t err;
    gpgme_data_t plain, cipher;
    err = gpgme_data_new(&plain);
    if (err) return err;
    err = gpgme_data_new_from_mem(&cipher, cipher_data, len_cipher, INT_TRUE);
    if (err) return err;
    err = gpgme_data_set_encoding(plain, GPGME_DATA_ENCODING_BINARY);
    if (err) return err;
    err = gpgme_data_set_flag(plain, SENSITIVE_FLAG, TEXT_TRUE);
    if (err) return err;
    err = gpgme_op_decrypt(ctx, cipher, plain);
    if (err) return err;
    gpgme_data_release(cipher);
    *plain_data = gpgme_data_release_and_get_mem(plain, len_plain);
    return GPG_ERR_NO_ERROR;
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

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void* base64_encode(void *src, size_t len, size_t *out_len, int sep) {
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;
	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	if (sep) olen += olen / 72; /* line feeds */
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

// -----=====| TYPES |=====-----

struct secret {
    char* data;
    size_t* esize;
    size_t* dsize;
};
typedef struct secret* secret_t;

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

// -----=====| SECRET |=====-----

gpgme_error_t secret_new(keyring_t kr, char* buf, size_t size, secret_t* ksecret) {
    gpgme_error_t err;
    (*ksecret) = gcry_malloc_secure(sizeof(struct secret));
    (*ksecret)->dsize = gcry_malloc_secure(sizeof(size_t));
    (*ksecret)->esize = gcry_malloc_secure(sizeof(size_t));
    *((*ksecret)->dsize) = size;
    err = encrypt_data(kr->ctx, kr->key, buf, &(*ksecret)->data, size, (*ksecret)->esize);
    if (err) return err;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_new_password(keyring_t kr, secret_t* ksecret) {
    gpgme_error_t err;
    char* buf = gcry_random_bytes_secure(SECRET_PASSWORD_LENGTH, GCRY_STRONG_RANDOM);
    char* buf_b64 = base64_encode(buf, SECRET_PASSWORD_LENGTH, NULL, 0);
    gcry_free(buf);
    err = secret_new(kr, buf_b64, SECRET_PASSWORD_B64_LENGTH, ksecret);
    gcry_free(buf_b64);
    if (err) return err;
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t secret_reveal(keyring_t kr, secret_t ksecret, char** buffer, size_t* size) {
    gpgme_error_t err;
    err = decrypt_data(kr->ctx, ksecret->data, buffer, *ksecret->esize, size);
    if (err) return err;
    if ((*size) != *ksecret->dsize) return GPG_ERR_USER_2;
    return GPG_ERR_NO_ERROR;
}

void secret_delete(secret_t ksecret) {
    gcry_free(ksecret->esize);
    gcry_free(ksecret->dsize);
    gpgme_free(ksecret->data);
    gcry_free(ksecret);
}

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
    secret_delete(rec->data);
    gcry_free(rec);
}


// password should be deleted with gpgme_free()
gpgme_error_t keyring_master_password(keyring_t kr, char** password) {
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
    *password = gpgme_data_release_and_get_mem(buf, NULL);
    return GPG_ERR_NO_ERROR;
}

gpgme_error_t keyring_generate_key(keyring_t kr, gpgme_key_t *key) {
    char* keyid;
    generate_uuid(&keyid);
    char* password_buf;
    keyring_master_password(kr, &password_buf);
    void* password_b64 = base64_encode(password_buf, SECRET_PASSWORD_LENGTH, NULL, 0);
    char* parms;
    compose_parms(keyid, password_b64, &parms);
    fprintf(stderr, "%s", parms);
    gpgme_op_genkey(kr->ctx, parms, NULL, NULL);
    gpgme_genkey_result_t res = gpgme_op_genkey_result(kr->ctx);
    gpgme_get_key(kr->ctx, res->fpr, key, 0);
    return 0;

}

int keyring_init(keyring_t* kr) {
    *kr = gcry_malloc_secure(sizeof(struct keyring));
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
    keyring_t kr;
    keyring_init(&kr);
    secret_t s;
    secret_new_password(kr, &s);
    keyring_record_t r;
    keyring_record_t r2;
    char* key = "foo";
    char* key2 = "bar";
    init_keyring_record(kr, s, key, 3, &r);
    init_keyring_record(kr, s, key2, 3, &r2);
    fprintf(stderr, "%d", keyring_compare_hashes(r, r2));
    return 0;
}
