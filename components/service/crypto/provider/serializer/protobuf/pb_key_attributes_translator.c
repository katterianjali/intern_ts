/*
 * Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "pb_key_attributes_translator.h"

void pb_crypto_provider_translate_key_attributes(psa_key_attributes_t *psa_attributes,
	const ts_crypto_KeyAttributes *proto_attributes) {

	psa_set_key_type(psa_attributes, proto_attributes->type);
	psa_set_key_bits(psa_attributes, proto_attributes->key_bits);
	psa_set_key_lifetime(psa_attributes, proto_attributes->lifetime);

	if (proto_attributes->lifetime == PSA_KEY_LIFETIME_PERSISTENT) {

		/* Note that namespace is set later */
		namespaced_key_id_t nsid;
		namespaced_key_id_init(&nsid, 0, proto_attributes->id);
		psa_set_key_id(psa_attributes, nsid);
	}

	if (proto_attributes->has_policy) {

		psa_set_key_usage_flags(psa_attributes, proto_attributes->policy.usage);
		psa_set_key_algorithm(psa_attributes, proto_attributes->policy.alg);
	}
}
