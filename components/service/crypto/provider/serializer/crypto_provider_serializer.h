/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CRYPTO_PROVIDER_SERIALIZER_H
#define CRYPTO_PROVIDER_SERIALIZER_H

#include <stddef.h>
#include <stdint.h>
#include <service/crypto/backend/crypto_backend.h>
#include <rpc/common/endpoint/rpc_interface.h>

/* Provides a common interface for parameter serialization operations
 * for the crypto service provider.  Allows alternative serialization
 * protocols to be used without hard-wiring a particular protocol
 * into the service provider code.  A concrete serializer must
 * implement this interface.
 */
struct crypto_provider_serializer {

    /* Returns the maximum deserialized parameter size that could
     * be encoded in a request buffer.  Used for determining worst-case
     * buffer size without having to actually deserialize the message.
     */
    size_t (*max_deserialised_parameter_size)(const struct call_param_buf *req_buf);

    /* Operation: generate_key */
    rpc_status_t (*deserialize_generate_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_attributes_t *attributes);

    rpc_status_t (*serialize_generate_key_resp)(struct call_param_buf *resp_buf,
                                        psa_key_id_t id);

    /* Operation: destroy_key */
    rpc_status_t (*deserialize_destroy_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id);

    /* Operation: export_key */
    rpc_status_t (*deserialize_export_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id);

    rpc_status_t (*serialize_export_key_resp)(struct call_param_buf *resp_buf,
                                        const uint8_t *data, size_t data_len);

    /* Operation: export_public_key */
    rpc_status_t (*deserialize_export_public_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id);

    rpc_status_t (*serialize_export_public_key_resp)(struct call_param_buf *resp_buf,
                                        const uint8_t *data, size_t data_len);

    /* Operation: import_key */
    rpc_status_t (*deserialize_import_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_attributes_t *attributes,
                                        uint8_t *data, size_t *data_len);

    rpc_status_t (*serialize_import_key_resp)(struct call_param_buf *resp_buf,
                                        psa_key_id_t id);

    /* Operation: copy_key */
    rpc_status_t (*deserialize_copy_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_attributes_t *attributes,
                                        psa_key_id_t *source_id);

    rpc_status_t (*serialize_copy_key_resp)(struct call_param_buf *resp_buf,
                                        psa_key_id_t target_id);

    /* Operation: purge_key */
    rpc_status_t (*deserialize_purge_key_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id);

    /* Operation: get_key_attributes */
    rpc_status_t (*deserialize_get_key_attributes_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id);

    rpc_status_t (*serialize_get_key_attributes_resp)(struct call_param_buf *resp_buf,
                                        const psa_key_attributes_t *attributes);

    /* Operation: sign_hash */
    rpc_status_t (*deserialize_asymmetric_sign_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id, psa_algorithm_t *alg,
                                        uint8_t *hash, size_t *hash_len);

    rpc_status_t (*serialize_asymmetric_sign_resp)(struct call_param_buf *resp_buf,
                                        const uint8_t *sig, size_t sig_len);

    /* Operation: verify_hash */
    rpc_status_t (*deserialize_asymmetric_verify_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id, psa_algorithm_t *alg,
                                        uint8_t *hash, size_t *hash_len,
                                        uint8_t *sig, size_t *sig_len);

    /* Operation: asymmetric_decrypt */
    rpc_status_t (*deserialize_asymmetric_decrypt_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id, psa_algorithm_t *alg,
                                        uint8_t *ciphertext, size_t *ciphertext_len,
                                        uint8_t *salt, size_t *salt_len);

    rpc_status_t (*serialize_asymmetric_decrypt_resp)(struct call_param_buf *resp_buf,
                                        const uint8_t *plaintext, size_t plaintext_len);

    /* Operation: asymmetric_encrypt */
    rpc_status_t (*deserialize_asymmetric_encrypt_req)(const struct call_param_buf *req_buf,
                                        psa_key_id_t *id, psa_algorithm_t *alg,
                                        uint8_t *plaintext, size_t *plaintext_len,
                                        uint8_t *salt, size_t *salt_len);

    rpc_status_t (*serialize_asymmetric_encrypt_resp)(struct call_param_buf *resp_buf,
                                        const uint8_t *ciphertext, size_t ciphertext_len);

    /* Operation: generate_random */
    rpc_status_t (*deserialize_generate_random_req)(const struct call_param_buf *req_buf,
                                        size_t *size);

    rpc_status_t (*serialize_generate_random_resp)(struct call_param_buf *resp_buf,
                                        const uint8_t *output, size_t output_len);
};

#endif /* CRYPTO_PROVIDER_SERIALIZER_H */
