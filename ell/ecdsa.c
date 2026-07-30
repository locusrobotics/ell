/*
 * Embedded Linux library
 * Copyright (C) 2024  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "private.h"
#include "useful.h"
#include "ecc.h"
#include "ecc-private.h"
#include "ecdsa-private.h"

/*
 * ECDSA signing — FIPS 186-4 Section 6.3.
 *
 * Both sign and verify operate on a *pre-computed* message digest supplied
 * by the caller.  The digest is left-padded with zeros if shorter than the
 * curve order, or truncated to the curve order size if longer (standard
 * ECDSA truncation rule).
 */
ssize_t ecdsa_sign(const struct l_ecc_scalar *privkey,
			const uint8_t *hash, size_t hash_len,
			uint8_t *out, size_t out_len)
{
	const struct l_ecc_curve *curve = privkey->curve;
	unsigned int ndigits = curve->ndigits;
	unsigned int nbytes  = ndigits * 8;
	struct l_ecc_point R;
	uint64_t k_vli[L_ECC_MAX_DIGITS];
	uint64_t r_vli[L_ECC_MAX_DIGITS];
	uint64_t s_vli[L_ECC_MAX_DIGITS];
	uint64_t z_vli[L_ECC_MAX_DIGITS];
	uint64_t tmp[L_ECC_MAX_DIGITS];
	uint64_t rd[L_ECC_MAX_DIGITS];
	uint64_t z_plus_rd[L_ECC_MAX_DIGITS];
	uint8_t z_buf[L_ECC_MAX_DIGITS * 8];
	uint8_t r_raw[L_ECC_MAX_DIGITS * 8];
	uint8_t s_raw[L_ECC_MAX_DIGITS * 8];
	uint8_t r_enc[L_ECC_MAX_DIGITS * 8 + 1];
	uint8_t s_enc[L_ECC_MAX_DIGITS * 8 + 1];
	unsigned int r_len, s_len, seq_len;
	unsigned int i;
	uint8_t *ptr;

	R.curve = curve;

	/* z = hash left-padded / right-truncated to nbytes, native VLI */
	memset(z_buf, 0, nbytes);
	if (hash_len >= nbytes)
		memcpy(z_buf, hash, nbytes);
	else
		memcpy(z_buf + nbytes - hash_len, hash, hash_len);
	_ecc_be2native(z_vli, (const uint64_t *)z_buf, ndigits);
	if (_vli_cmp(z_vli, curve->n, ndigits) >= 0)
		_vli_sub(z_vli, z_vli, curve->n, ndigits);

	for (i = 0; i < 10; i++) {
		_auto_(l_ecc_scalar_free) struct l_ecc_scalar *k_scalar =
			l_ecc_scalar_new_random(curve);
		if (!k_scalar)
			return -ENOMEM;
		memcpy(k_vli, k_scalar->c, nbytes);

		/* R = k * G */
		_ecc_point_mult(&R, &curve->g, k_vli, NULL, curve->p);
		if (_ecc_point_is_zero(&R))
			continue;

		/* r = R.x mod n */
		memcpy(r_vli, R.x, nbytes);
		if (_vli_cmp(r_vli, curve->n, ndigits) >= 0)
			_vli_sub(r_vli, r_vli, curve->n, ndigits);
		if (_vli_is_zero_or_one(r_vli, ndigits))
			continue;

		/* k_inv = k^(-1) mod n */
		_vli_mod_inv(tmp, k_vli, curve->n, ndigits);

		/* s = k_inv * (z + r*d) mod n */
		_vli_mod_mult_slow(rd, r_vli, privkey->c, curve->n, ndigits);
		_vli_mod_add(z_plus_rd, z_vli, rd, curve->n, ndigits);
		_vli_mod_mult_slow(s_vli, tmp, z_plus_rd, curve->n, ndigits);

		if (_vli_is_zero_or_one(s_vli, ndigits))
			continue;

		break;
	}

	if (i >= 10)
		return -EAGAIN;

	/* Convert r and s to big-endian */
	_ecc_native2be((uint64_t *)r_raw, r_vli, ndigits);
	_ecc_native2be((uint64_t *)s_raw, s_vli, ndigits);

	/* DER INTEGER encoding: strip leading zeros, add 0x00 if high bit set */
#define DER_INTEGER_ENCODE(raw, enc, len) do {				\
		unsigned int skip = 0;					\
		while (skip < nbytes - 1 && !(raw)[skip] &&		\
				!((raw)[skip + 1] & 0x80))		\
			skip++;						\
		if ((raw)[skip] & 0x80) {				\
			(enc)[0] = 0x00;				\
			memcpy((enc) + 1, (raw) + skip, nbytes - skip); \
			(len) = nbytes - skip + 1;			\
		} else {						\
			memcpy((enc), (raw) + skip, nbytes - skip);	\
			(len) = nbytes - skip;				\
		}							\
	} while (0)

	DER_INTEGER_ENCODE(r_raw, r_enc, r_len);
	DER_INTEGER_ENCODE(s_raw, s_enc, s_len);
#undef DER_INTEGER_ENCODE

	seq_len = 2 + r_len + 2 + s_len;
	if (out_len < (size_t)(2 + seq_len))
		return -EMSGSIZE;

	ptr = out;
	*ptr++ = 0x30;
	*ptr++ = seq_len;
	*ptr++ = 0x02;
	*ptr++ = r_len;
	memcpy(ptr, r_enc, r_len); ptr += r_len;
	*ptr++ = 0x02;
	*ptr++ = s_len;
	memcpy(ptr, s_enc, s_len); ptr += s_len;

	return ptr - out;
}

/*
 * ECDSA verification.
 *
 * Parses the DER Ecdsa-Sig-Value then computes X = u1*G + u2*Q and
 * checks that X.x mod n equals r.
 */
bool ecdsa_verify(const struct l_ecc_point *pubkey,
			const uint8_t *hash, size_t hash_len,
			const uint8_t *sig, size_t sig_len)
{
	const struct l_ecc_curve *curve = pubkey->curve;
	unsigned int ndigits = curve->ndigits;
	unsigned int nbytes  = ndigits * 8;
	uint64_t r[L_ECC_MAX_DIGITS], s[L_ECC_MAX_DIGITS];
	uint64_t z[L_ECC_MAX_DIGITS];
	uint64_t w[L_ECC_MAX_DIGITS];
	uint64_t u1[L_ECC_MAX_DIGITS], u2[L_ECC_MAX_DIGITS];
	struct l_ecc_point X1, X2, X;
	const uint8_t *ptr = sig;
	size_t len = sig_len;
	uint16_t seq_len, r_len, s_len;
	uint8_t r_buf[L_ECC_MAX_DIGITS * 8];
	uint8_t s_buf[L_ECC_MAX_DIGITS * 8];

	/* Parse DER SEQUENCE { INTEGER r, INTEGER s } */
	if (len < 2 || *ptr++ != 0x30)
		return false;
	seq_len = *ptr++;
	len -= 2;
	if (seq_len != len)
		return false;

	/* r */
	if (len < 2 || *ptr++ != 0x02)
		return false;
	r_len = *ptr++;
	len -= 2;
	if (r_len > len || r_len == 0)
		return false;
	if (*ptr == 0x00 && r_len > 1) { ptr++; r_len--; len--; }
	if (r_len > nbytes)
		return false;
	memset(r_buf, 0, nbytes);
	memcpy(r_buf + nbytes - r_len, ptr, r_len);
	ptr += r_len; len -= r_len;

	/* s */
	if (len < 2 || *ptr++ != 0x02)
		return false;
	s_len = *ptr++;
	len -= 2;
	if (s_len > len || s_len == 0)
		return false;
	if (*ptr == 0x00 && s_len > 1) { ptr++; s_len--; len--; }
	if (s_len > nbytes)
		return false;
	memset(s_buf, 0, nbytes);
	memcpy(s_buf + nbytes - s_len, ptr, s_len);

	_ecc_be2native(r, (const uint64_t *)r_buf, ndigits);
	_ecc_be2native(s, (const uint64_t *)s_buf, ndigits);

	if (_vli_is_zero_or_one(r, ndigits) ||
			_vli_cmp(r, curve->n, ndigits) >= 0)
		return false;
	if (_vli_is_zero_or_one(s, ndigits) ||
			_vli_cmp(s, curve->n, ndigits) >= 0)
		return false;

	/* z = hash left-padded / right-truncated to nbytes, native VLI */
	{
		uint8_t z_buf[L_ECC_MAX_DIGITS * 8] = {};
		unsigned int copy = (hash_len < nbytes) ? hash_len : nbytes;
		memcpy(z_buf + nbytes - copy, hash + hash_len - copy, copy);
		_ecc_be2native(z, (const uint64_t *)z_buf, ndigits);
		if (_vli_cmp(z, curve->n, ndigits) >= 0)
			_vli_sub(z, z, curve->n, ndigits);
	}

	/* w = s^(-1) mod n */
	_vli_mod_inv(w, s, curve->n, ndigits);

	/* u1 = z*w mod n,  u2 = r*w mod n */
	_vli_mod_mult_slow(u1, z, w, curve->n, ndigits);
	_vli_mod_mult_slow(u2, r, w, curve->n, ndigits);

	/* X = u1*G + u2*Q */
	X1.curve = curve;
	X2.curve = curve;
	X.curve  = curve;
	_ecc_point_mult(&X1, &curve->g,  u1, NULL, curve->p);
	_ecc_point_mult(&X2, pubkey,     u2, NULL, curve->p);
	_ecc_point_add(&X, &X1, &X2, curve->p);

	if (_ecc_point_is_zero(&X))
		return false;

	/* Verify X.x mod n == r */
	{
		uint64_t x_mod_n[L_ECC_MAX_DIGITS];
		memcpy(x_mod_n, X.x, nbytes);
		if (_vli_cmp(x_mod_n, curve->n, ndigits) >= 0)
			_vli_sub(x_mod_n, x_mod_n, curve->n, ndigits);
		return _vli_cmp(x_mod_n, r, ndigits) == 0;
	}
}
