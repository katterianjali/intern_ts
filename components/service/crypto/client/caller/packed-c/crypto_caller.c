/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CRYPTO_CALLER_IMPORT_KEY_H
#define PACKEDC_CRYPTO_CALLER_IMPORT_KEY_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <psa/crypto.h>
#include <service/common/client/service_client.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/crypto/packed-c/opcodes.h>
#include <protocols/service/crypto/packed-c/key_attributes.h>
#include <protocols/service/crypto/packed-c/import_key.h>
#include <protocols/service/crypto/packed-c/export_key.h>
#include <protocols/service/crypto/packed-c/hash.h>
#include <common/tlv/tlv.h>
#include <psa/initial_attestation.h>
#include <protocols/service/attestation/packed-c/get_token.h>
#include <protocols/service/attestation/packed-c/get_token_size.h>
#include <protocols/service/attestation/packed-c/opcodes.h>

#include "crypto_caller_key_attributes.h"
#include "crypto_caller_ext.h"



#ifdef __cplusplus
extern "C" {
#endif

psa_status_t crypto_caller_import_key_ext(struct service_client *context,
	const psa_key_attributes_t *attributes,
	const uint8_t *data, size_t data_length,
	psa_key_id_t *id)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_import_key_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_import_key_in);
	size_t req_len = req_fixed_len + tlv_required_space(data_length);
	long unsigned int i;

    psa_key_lifetime_t lifetime = psa_get_key_lifetime( attributes );
	/* Set default outputs for failure case */
	*id = 0;
	packedc_crypto_caller_translate_key_attributes_to_proto(&req_msg.attributes, attributes);

	struct tlv_record key_record;
	key_record.tag = TS_CRYPTO_IMPORT_KEY_IN_TAG_DATA;
	key_record.length = data_length;
	key_record.value = data;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;
		struct tlv_iterator req_iter;

		memcpy(req_buf, &req_msg, req_fixed_len);

		tlv_iterator_begin(&req_iter, &req_buf[req_fixed_len], req_len - req_fixed_len);
		tlv_encode(&req_iter, &key_record);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
						TS_CRYPTO_OPCODE_IMPORT_KEY, &opstatus, &resp_buf, &resp_len);
		

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_crypto_import_key_out)) {

					struct ts_crypto_import_key_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_crypto_import_key_out));
					*id = resp_msg.id;
					
				}
				else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}


psa_status_t crypto_caller_export_key_ext(struct service_client *context,
	psa_key_id_t id,
	uint8_t *data, size_t data_size, size_t *data_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_export_key_in req_msg;
	size_t req_len = sizeof(struct ts_crypto_export_key_in);

	req_msg.id = id;
	//printf("\n crypto_caller_export_key_ext %x\n",id);
	*data_length = 0; /* For failure case */

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;

		memcpy(req_buf, &req_msg, req_len);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
					TS_CRYPTO_OPCODE_EXPORT_KEY, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;
				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
						TS_CRYPTO_EXPORT_KEY_OUT_TAG_DATA, &decoded_record)) {

					//printf("\ncrypto_caller_export_key_ext %d %ld\n",decoded_record.length,data_size);

					if (decoded_record.length <= data_size) {

						memcpy(data, decoded_record.value, decoded_record.length);
						*data_length = decoded_record.length;
					/*	for(unsigned long int i=0;i < decoded_record.length;i++){
      		      			printf(" %x " , *(decoded_record.value +i));
 			   			}*/
					}
					else {
						/* Provided buffer is too small */
						psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
					}
				}
				else {
					/* Mandatory response parameter missing */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}
 
psa_status_t crypto_caller_hash_setup_ext(struct service_client *context,
	uint32_t *op_handle,
	psa_algorithm_t alg)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_hash_setup_in req_msg;
	size_t req_len = sizeof(struct ts_crypto_hash_setup_in);

	req_msg.alg = alg;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;

		memcpy(req_buf, &req_msg, req_len);
		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
				TS_CRYPTO_OPCODE_HASH_SETUP, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_crypto_hash_setup_out)) {

					struct ts_crypto_hash_setup_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_crypto_hash_setup_out));
					*op_handle = resp_msg.op_handle;
				}
				else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}


psa_status_t crypto_caller_hash_update_ext(struct service_client *context,
	uint32_t op_handle,
	const uint8_t *input,
	size_t input_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_hash_update_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_hash_update_in);
	size_t req_len = req_fixed_len;

	req_msg.op_handle = op_handle;

	/* Mandatory input data parameter */
	struct tlv_record data_record;
	data_record.tag = TS_CRYPTO_HASH_UPDATE_IN_TAG_DATA;
	data_record.length = input_length;
	data_record.value = input;
	req_len += tlv_required_space(data_record.length);

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;
		struct tlv_iterator req_iter;

		memcpy(req_buf, &req_msg, req_fixed_len);

		tlv_iterator_begin(&req_iter, &req_buf[req_fixed_len], req_len - req_fixed_len);
		tlv_encode(&req_iter, &data_record);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
				TS_CRYPTO_OPCODE_HASH_UPDATE, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

psa_status_t crypto_caller_hash_finish_ext(struct service_client *context,
	uint32_t op_handle,
	uint8_t *hash,
	size_t hash_size,
	size_t *hash_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_hash_finish_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_hash_finish_in);
	size_t req_len = req_fixed_len;

	*hash_length = 0;
	req_msg.op_handle = op_handle;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;

		memcpy(req_buf, &req_msg, req_fixed_len);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
				TS_CRYPTO_OPCODE_HASH_FINISH, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;
				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
					TS_CRYPTO_HASH_FINISH_OUT_TAG_HASH, &decoded_record)) {

					if (decoded_record.length <= hash_size) {

						memcpy(hash, decoded_record.value, decoded_record.length);
						*hash_length = decoded_record.length;
					}
					else {
						/* Provided buffer is too small */
						psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
					}
				}
				else {
					/* Mandatory response parameter missing */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}


psa_status_t crypto_caller_hash_abort_ext(struct service_client *context,
	uint32_t op_handle)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_hash_abort_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_hash_abort_in);
	size_t req_len = req_fixed_len;

	req_msg.op_handle = op_handle;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;

		memcpy(req_buf, &req_msg, req_fixed_len);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
				TS_CRYPTO_OPCODE_HASH_ABORT, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

psa_status_t crypto_caller_hash_verify_ext(struct service_client *context,
	uint32_t op_handle,
	const uint8_t *hash,
	size_t hash_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_hash_verify_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_hash_verify_in);
	size_t req_len = req_fixed_len;

	req_msg.op_handle = op_handle;

	/* Mandatory input data parameter */
	struct tlv_record data_record;
	data_record.tag = TS_CRYPTO_HASH_VERIFY_IN_TAG_HASH;
	data_record.length = hash_length;
	data_record.value = hash;
	req_len += tlv_required_space(data_record.length);

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;
		struct tlv_iterator req_iter;

		memcpy(req_buf, &req_msg, req_fixed_len);

		tlv_iterator_begin(&req_iter, &req_buf[req_fixed_len], req_len - req_fixed_len);
		tlv_encode(&req_iter, &data_record);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
				TS_CRYPTO_OPCODE_HASH_VERIFY, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

psa_status_t crypto_caller_hash_clone_ext(struct service_client *context,
	uint32_t source_op_handle,
	uint32_t *target_op_handle)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_hash_clone_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_hash_clone_in);
	size_t req_len = req_fixed_len;

	req_msg.source_op_handle = source_op_handle;

	rpc_call_handle call_handle;
	uint8_t *req_buf;

	call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

	if (call_handle) {

		uint8_t *resp_buf;
		size_t resp_len;
		rpc_opstatus_t opstatus;

		memcpy(req_buf, &req_msg, req_fixed_len);

		context->rpc_status =
			rpc_caller_invoke(context->caller, call_handle,
				TS_CRYPTO_OPCODE_HASH_CLONE, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_crypto_hash_clone_out)) {

					struct ts_crypto_hash_clone_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_crypto_hash_clone_out));
					*target_op_handle = resp_msg.target_op_handle;
				}
				else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
			}
		}

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}


psa_status_t psa_initial_attest_get_token_ext(struct service_client *context,
	const uint8_t *auth_challenge, size_t challenge_size,
    uint8_t *token_buf, size_t token_buf_size, size_t *token_size)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
    size_t req_len = tlv_required_space(challenge_size);

    if (!token_buf || !token_buf_size) return PSA_ERROR_INVALID_ARGUMENT;

    struct tlv_record challenge_record;
    challenge_record.tag = TS_ATTESTATION_GET_TOKEN_IN_TAG_AUTH_CHALLENGE;
    challenge_record.length = challenge_size;
    challenge_record.value = auth_challenge;

    rpc_call_handle call_handle;
    uint8_t *req_buf;

	*token_size = 0;

    call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

    if (call_handle) {

        uint8_t *resp_buf;
        size_t resp_len;
        rpc_opstatus_t opstatus;
        struct tlv_iterator req_iter;

        tlv_iterator_begin(&req_iter, req_buf, req_len);
        tlv_encode(&req_iter, &challenge_record);

        context->rpc_status = rpc_caller_invoke(context->caller, call_handle,
            TS_ATTESTATION_OPCODE_GET_TOKEN, &opstatus, &resp_buf, &resp_len);

        if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

            psa_status = opstatus;

            if (psa_status == PSA_SUCCESS) {

                struct tlv_const_iterator resp_iter;
                struct tlv_record decoded_record;
                tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

                if (tlv_find_decode(&resp_iter,
						TS_ATTESTATION_GET_TOKEN_OUT_TAG_TOKEN, &decoded_record)) {

                    if (decoded_record.length <= token_buf_size) {

                        memcpy(token_buf, decoded_record.value, decoded_record.length);
                        *token_size = decoded_record.length;
                    }
                    else {
                        /* Provided buffer is too small */
                        psa_status = PSA_ERROR_BUFFER_TOO_SMALL;
                    }
                }
                else {
                    /* Mandatory response parameter missing */
                    psa_status = PSA_ERROR_GENERIC_ERROR;
                }
			}
        }

        rpc_caller_end(context->caller, call_handle);
    }

    return psa_status;
}

psa_status_t psa_initial_attest_get_token_size_ext(struct service_client *context,
	size_t challenge_size, size_t *token_size)
{
    psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
    struct ts_attestation_get_token_size_in req_msg;
    size_t req_len = sizeof(struct ts_attestation_get_token_size_in);

    *token_size = 0;  /* For failure case */

    req_msg.challenge_size = challenge_size;

    rpc_call_handle call_handle;
    uint8_t *req_buf;

    call_handle = rpc_caller_begin(context->caller, &req_buf, req_len);

    if (call_handle) {

        uint8_t *resp_buf;
        size_t resp_len;
        rpc_opstatus_t opstatus;
        struct tlv_iterator req_iter;

        memcpy(req_buf, &req_msg, req_len);

       context->rpc_status = rpc_caller_invoke(context->caller, call_handle,
                    TS_ATTESTATION_OPCODE_GET_TOKEN_SIZE, &opstatus, &resp_buf, &resp_len);

        if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

            psa_status = opstatus;

            if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_attestation_get_token_size_out)) {

					struct ts_attestation_get_token_size_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_attestation_get_token_size_out));
					*token_size = resp_msg.token_size;
				}
				else {
					/* Failed to decode response message */
					psa_status = PSA_ERROR_GENERIC_ERROR;
				}
            }
        }

        rpc_caller_end(context->caller, call_handle);
    }

    return psa_status;
}

#ifdef __cplusplus
}
#endif

#endif /* PACKEDC_CRYPTO_CALLER_IMPORT_KEY_H */
