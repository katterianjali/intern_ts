/*
 * Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PACKEDC_CRYPTO_CALLER_AEAD_H
#define PACKEDC_CRYPTO_CALLER_AEAD_H

#include <string.h>
#include <stdlib.h>
#include <psa/crypto.h>
#include <service/common/client/service_client.h>
#include <protocols/rpc/common/packed-c/status.h>
#include <protocols/service/crypto/packed-c/opcodes.h>
#include <protocols/service/crypto/packed-c/aead.h>
#include <common/tlv/tlv.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline psa_status_t crypto_caller_aead_encrypt(struct service_client *context,
	psa_key_id_t key,
	psa_algorithm_t alg,
	const uint8_t *nonce,
	size_t nonce_length,
	const uint8_t *additional_data,
	size_t additional_data_length,
	const uint8_t *plaintext,
	size_t plaintext_length,
	uint8_t *aeadtext,
	size_t aeadtext_size,
	size_t *aeadtext_length)
{
	return PSA_ERROR_NOT_SUPPORTED;
}

static inline psa_status_t crypto_caller_aead_decrypt(struct service_client *context,
	psa_key_id_t key,
	psa_algorithm_t alg,
	const uint8_t *nonce,
	size_t nonce_length,
	const uint8_t *additional_data,
	size_t additional_data_length,
	const uint8_t *aeadtext,
	size_t aeadtext_length,
	uint8_t *plaintext,
	size_t plaintext_size,
	size_t *plaintext_length)
{
	return PSA_ERROR_NOT_SUPPORTED;
}

static inline psa_status_t common_aead_setup(struct service_client *context,
	uint32_t *op_handle,
	psa_key_id_t key,
	psa_algorithm_t alg,
	uint32_t opcode)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_setup_in req_msg;
	size_t req_len = sizeof(struct ts_crypto_aead_setup_in);

	req_msg.key_id = key;
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
				opcode, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				if (resp_len >= sizeof(struct ts_crypto_aead_setup_out)) {

					struct ts_crypto_aead_setup_out resp_msg;
					memcpy(&resp_msg, resp_buf, sizeof(struct ts_crypto_aead_setup_out));
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

static inline psa_status_t crypto_caller_aead_encrypt_setup(struct service_client *context,
	uint32_t *op_handle,
	psa_key_id_t key,
	psa_algorithm_t alg)
{
	return common_aead_setup(context,
		op_handle, key, alg, TS_CRYPTO_OPCODE_AEAD_ENCRYPT_SETUP);
}

static inline psa_status_t crypto_caller_aead_decrypt_setup(struct service_client *context,
	uint32_t *op_handle,
	psa_key_id_t key,
	psa_algorithm_t alg)
{
	return common_aead_setup(context,
		op_handle, key, alg, TS_CRYPTO_OPCODE_AEAD_DECRYPT_SETUP);
}

static inline psa_status_t crypto_caller_aead_generate_nonce(struct service_client *context,
	uint32_t op_handle,
	uint8_t *nonce,
	size_t nonce_size,
	size_t *nonce_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_generate_nonce_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_generate_nonce_in);
	size_t req_len = req_fixed_len;

	*nonce_length = 0;
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
				TS_CRYPTO_OPCODE_AEAD_GENERATE_NONCE, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;
				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
					TS_CRYPTO_AEAD_GENERATE_NONCE_OUT_TAG_NONCE, &decoded_record)) {

					if (decoded_record.length <= nonce_size) {

						memcpy(nonce, decoded_record.value, decoded_record.length);
						*nonce_length = decoded_record.length;
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

static inline psa_status_t crypto_caller_aead_set_nonce(struct service_client *context,
	uint32_t op_handle,
	const uint8_t *nonce,
	size_t nonce_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_set_nonce_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_set_nonce_in);
	size_t req_len = req_fixed_len;

	req_msg.op_handle = op_handle;

	/* Mandatory input data parameter */
	struct tlv_record data_record;
	data_record.tag = TS_CRYPTO_AEAD_SET_NONCE_IN_TAG_NONCE;
	data_record.length = nonce_length;
	data_record.value = nonce;
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
				TS_CRYPTO_OPCODE_AEAD_SET_NONCE, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

static inline psa_status_t crypto_caller_aead_set_lengths(struct service_client *context,
	uint32_t op_handle,
	size_t ad_length,
	size_t plaintext_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_set_lengths_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_abort_in);
	size_t req_len = req_fixed_len;

	req_msg.op_handle = op_handle;
	req_msg.ad_length = ad_length;
	req_msg.plaintext_length = plaintext_length;

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
				TS_CRYPTO_OPCODE_AEAD_SET_LENGTHS, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

static inline psa_status_t crypto_caller_aead_update_ad(struct service_client *context,
	uint32_t op_handle,
	const uint8_t *input,
	size_t input_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_update_ad_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_update_ad_in);
	size_t req_len = req_fixed_len;

	req_msg.op_handle = op_handle;

	/* Mandatory input data parameter */
	struct tlv_record data_record;
	data_record.tag = TS_CRYPTO_AEAD_UPDATE_AD_IN_TAG_DATA;
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
				TS_CRYPTO_OPCODE_AEAD_UPDATE_AD, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

static inline psa_status_t crypto_caller_aead_update(struct service_client *context,
	uint32_t op_handle,
	const uint8_t *input,
	size_t input_length,
	uint8_t *output,
	size_t output_size,
	size_t *output_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_update_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_update_in);
	size_t req_len = req_fixed_len;

	*output_length = 0;
	req_msg.op_handle = op_handle;

	/* Mandatory input data parameter */
	struct tlv_record data_record;
	data_record.tag = TS_CRYPTO_AEAD_UPDATE_IN_TAG_DATA;
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
				TS_CRYPTO_OPCODE_AEAD_UPDATE, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;
				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
					TS_CRYPTO_AEAD_UPDATE_OUT_TAG_DATA, &decoded_record)) {

					if (decoded_record.length <= output_size) {

						memcpy(output, decoded_record.value, decoded_record.length);
						*output_length = decoded_record.length;
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

static inline psa_status_t crypto_caller_aead_finish(struct service_client *context,
	uint32_t op_handle,
	uint8_t *aeadtext,
	size_t aeadtext_size,
	size_t *aeadtext_length,
	uint8_t *tag,
	size_t tag_size,
	size_t *tag_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_finish_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_finish_in);
	size_t req_len = req_fixed_len;

	*aeadtext_length = 0;
	*tag_length = 0;
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
				TS_CRYPTO_OPCODE_AEAD_FINISH, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;
				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
					TS_CRYPTO_AEAD_FINISH_OUT_TAG_CIPHERTEXT, &decoded_record)) {

					if (decoded_record.length <= aeadtext_size) {

						memcpy(aeadtext, decoded_record.value, decoded_record.length);
						*aeadtext_length = decoded_record.length;
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

				if ((psa_status == PSA_SUCCESS) && tlv_find_decode(&resp_iter,
					TS_CRYPTO_AEAD_FINISH_OUT_TAG_TAG, &decoded_record)) {

					if (decoded_record.length <= tag_size) {

						memcpy(tag, decoded_record.value, decoded_record.length);
						*tag_length = decoded_record.length;
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

static inline psa_status_t crypto_caller_aead_verify(struct service_client *context,
	uint32_t op_handle,
	uint8_t *plaintext,
	size_t plaintext_size,
	size_t *plaintext_length,
	const uint8_t *tag,
	size_t tag_length)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_verify_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_verify_in);
	size_t req_len = req_fixed_len;

	*plaintext_length = 0;
	req_msg.op_handle = op_handle;

	/* Mandatory input data parameter */
	struct tlv_record data_record;
	data_record.tag = TS_CRYPTO_AEAD_VERIFY_IN_TAG_TAG;
	data_record.length = tag_length;
	data_record.value = tag;
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
				TS_CRYPTO_OPCODE_AEAD_VERIFY, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) {

			psa_status = opstatus;

			if (psa_status == PSA_SUCCESS) {

				struct tlv_const_iterator resp_iter;
				struct tlv_record decoded_record;
				tlv_const_iterator_begin(&resp_iter, resp_buf, resp_len);

				if (tlv_find_decode(&resp_iter,
					TS_CRYPTO_AEAD_VERIFY_OUT_TAG_PLAINTEXT, &decoded_record)) {

					if (decoded_record.length <= plaintext_size) {

						memcpy(plaintext, decoded_record.value, decoded_record.length);
						*plaintext_length = decoded_record.length;
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

static inline psa_status_t crypto_caller_aead_abort(struct service_client *context,
	uint32_t op_handle)
{
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	struct ts_crypto_aead_abort_in req_msg;
	size_t req_fixed_len = sizeof(struct ts_crypto_aead_abort_in);
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
				TS_CRYPTO_OPCODE_AEAD_ABORT, &opstatus, &resp_buf, &resp_len);

		if (context->rpc_status == TS_RPC_CALL_ACCEPTED) psa_status = opstatus;

		rpc_caller_end(context->caller, call_handle);
	}

	return psa_status;
}

#ifdef __cplusplus
}
#endif

#endif /* PACKEDC_CRYPTO_CALLER_AEAD_H */
