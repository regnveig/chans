#include "base64.h"

// result should be deleted via gcry_free()
void* base64_encode(void *src, size_t len, size_t *out_len, int sep) {
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;
	olen = len * 4 / 3 + 4;
	if (sep) olen += olen / 72;
	olen++;
	if (olen < len) return NULL;
	out = gcry_malloc_secure(olen);
	if (!out) return NULL;
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
        if (sep) {
            line_len += 4;
            if (line_len >= 72) {
                *pos++ = '\n';
                line_len = 0;
            }
        }
	}
	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		if (sep) line_len += 4;
	}
    if (sep) {
        if (line_len) *pos++ = '\n';
    }
	*pos = '\0';
	if (out_len) *out_len = pos - out;
	return out;
}
