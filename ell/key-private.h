/*
 * Embedded Linux library
 * Copyright (C) 2024  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

struct l_ecc_scalar;
struct l_ecc_point;

struct l_key *key_new_ec_private(const struct l_ecc_scalar *scalar);
struct l_key *key_new_ec_public(const struct l_ecc_point *point);
