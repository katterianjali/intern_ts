/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CALLER_CLIENT_H
#define CALLER_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <psa/crypto.h>

/*
 * The rpc_caller puplic interface may be exported as a public interface to
 * a shared library.
 */
#ifdef EXPORT_PUBLIC_INTERFACE_CALLER_CLIENT
#define CALLER_CLIENT_EXPORTED __attribute__((__visibility__("default")))
#else
#define CALLER_CLIENT_EXPORTED
#endif


#ifdef __cplusplus
extern "C" {
#endif

CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_import_key_ext(struct service_client *context,
	const psa_key_attributes_t *attributes,
	const uint8_t *data, size_t data_length,
	psa_key_id_t *id);

CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_export_key_ext(struct service_client *context,
    psa_key_id_t id,
    uint8_t *data, size_t data_size, size_t *data_length);

CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_hash_setup_ext(struct service_client *context,
    uint32_t *op_handle,
    psa_algorithm_t alg);

CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_hash_update_ext(struct service_client *context,
    uint32_t op_handle,
    const uint8_t *input,
    size_t input_length);
CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_hash_finish_ext(struct service_client *context,
    uint32_t op_handle,
    uint8_t *hash,
    size_t hash_size,
    size_t *hash_length);

CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_hash_abort_ext(struct service_client *context,
    uint32_t op_handle);

CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_hash_verify_ext(struct service_client *context,
    uint32_t op_handle,
    const uint8_t *hash,
    size_t hash_length);
CALLER_CLIENT_EXPORTED psa_status_t crypto_caller_hash_clone_ext(struct service_client *context,
    uint32_t source_op_handle,
    uint32_t *target_op_handle);

CALLER_CLIENT_EXPORTED psa_status_t psa_initial_attest_get_token_ext(struct service_client *context,
    const uint8_t *auth_challenge, size_t challenge_size,
    uint8_t *token_buf, size_t token_buf_size, size_t *token_size);

CALLER_CLIENT_EXPORTED psa_status_t psa_initial_attest_get_token_size_ext(struct service_client *context,
    size_t challenge_size, size_t *token_size);

#ifdef __cplusplus
}
#endif

#endif 
