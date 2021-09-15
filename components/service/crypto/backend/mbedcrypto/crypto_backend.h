/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MBEDTLS_CRYPTO_BACKEND_H
#define MBEDTLS_CRYPTO_BACKEND_H

/**
 * A crypto backend that uses a configuration of mbedtls to provide the
 * backend interface used by a crypto provider.  The build configuration
 * enables namespacing of key ids.
 */
#ifdef MBEDTLS_PSA_CRYPTO_H
#include MBEDTLS_PSA_CRYPTO_H
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Mbedtls supports key id namespacing via the mbedtls_svc_key_id_t
 * type that combines a key id with an owner id.
 */
typedef mbedtls_svc_key_id_t namespaced_key_id_t;

/**
 * Map to the mbedtls owner id type for the namespace.
 */
typedef mbedtls_key_owner_id_t key_id_namespace_t;

/**
 * \brief Initialize a namespaced key id
 *
 * This default implementation just discards the namespace.
 *
 * \param ns_key_id  	The object to initialize
 * \param ns          	The namespace
 * \param key_id		The key id
 */
static inline void namespaced_key_id_init(
	namespaced_key_id_t *ns_key_id,
	key_id_namespace_t ns,
	psa_key_id_t key_id)
{
	ns_key_id->MBEDTLS_PRIVATE(key_id) = key_id;
    ns_key_id->MBEDTLS_PRIVATE(owner) = ns;
}

/**
 * \brief Get the key id from a namespaced_key_id_t
 *
 * \param ns_key_id  The object to initialize
 * \return Key id without namespace
 */
static inline psa_key_id_t namespaced_key_id_get_key_id(
	namespaced_key_id_t ns_key_id)
{
	return ns_key_id.MBEDTLS_PRIVATE(key_id);
}

/**
 * \brief Set the key id namespace associated with a key attributes object
 *
 * The default implementation discards the namespace
 *
 * \param attributes 	Key attributes object
 * \param ns  			Key is namespace
 */
static inline void namespaced_key_id_set_namespace(
	psa_key_attributes_t *attributes,
	key_id_namespace_t ns)
{
    mbedtls_set_key_owner_id(attributes, ns);
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MBEDTLS_CRYPTO_BACKEND_H  */
