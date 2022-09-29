/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c for more details.
 */

#ifndef BASE64_H
#define BASE64_H

#include <gcrypt.h>
#include <stddef.h>

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void* base64_encode(void *src, size_t len, size_t *out_len, int sep);

#endif // BASE64_H
