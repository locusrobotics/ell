/*
 * Embedded Linux library
 * Copyright (C) 2024  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

struct l_ecc_scalar;
struct l_ecc_point;

/*
 * Maximum byte length of a DER-encoded Ecdsa-Sig-Value for any curve
 * supported by ELL:  SEQUENCE(INTEGER(r), INTEGER(s)) with each integer
 * at most (ndigits*8 + 1) bytes.
 */
#define ECDSA_MAX_DER_SIG  (2 + 2 * (2 + 1 + 8 * 8))  /* 66 bytes for P-521 */

/*
 * Sign a pre-computed message digest with a software EC private key.
 *
 * @privkey:  EC private scalar (l_ecc_scalar from key_new_ec_private)
 * @hash:     Message digest bytes (pre-hashed by the caller)
 * @hash_len: Length of @hash
 * @out:      Output buffer for the DER Ecdsa-Sig-Value
 * @out_len:  Capacity of @out (>= ECDSA_MAX_DER_SIG is always sufficient)
 *
 * Returns the number of bytes written to @out on success, or a negative
 * errno on failure (-ENOMEM, -EAGAIN, -EMSGSIZE).
 */
ssize_t ecdsa_sign(const struct l_ecc_scalar *privkey,
			const uint8_t *hash, size_t hash_len,
			uint8_t *out, size_t out_len);

/*
 * Verify a DER-encoded Ecdsa-Sig-Value against a pre-computed message
 * digest using a software EC public key.
 *
 * @pubkey:   EC public point (l_ecc_point from key_new_ec_public)
 * @hash:     Message digest bytes (pre-hashed by the caller)
 * @hash_len: Length of @hash
 * @sig:      DER Ecdsa-Sig-Value
 * @sig_len:  Length of @sig
 *
 * Returns true if the signature is valid, false otherwise.
 */
bool ecdsa_verify(const struct l_ecc_point *pubkey,
			const uint8_t *hash, size_t hash_len,
			const uint8_t *sig, size_t sig_len);
