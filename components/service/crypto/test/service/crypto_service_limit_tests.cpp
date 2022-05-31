/*
 * Copyright (c) 2020-2022, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <service/crypto/client/cpp/protocol/protobuf/protobuf_crypto_client.h>
#include <protocols/rpc/common/packed-c/encoding.h>
#include <service_locator.h>
#include <CppUTest/TestHarness.h>

/*
 * Service-level tests that focus on verifying that expected limits are met.
 * e.g. number of keys, key sizes etc.
 */
TEST_GROUP(CryptoServiceLimitTests)
{
    void setup()
    {
        struct rpc_caller *caller;
        int status;

        m_rpc_session_handle = NULL;
        m_crypto_service_context = NULL;
        m_crypto_client = NULL;

        service_locator_init();

        m_crypto_service_context = service_locator_query("sn:trustedfirmware.org:crypto:0", &status);
        CHECK(m_crypto_service_context);

        m_rpc_session_handle = service_context_open(m_crypto_service_context, TS_RPC_ENCODING_PROTOBUF, &caller);
        CHECK(m_rpc_session_handle);

        m_crypto_client = new protobuf_crypto_client(caller);
    }

    void teardown()
    {
        delete m_crypto_client;
        m_crypto_client = NULL;

	if (m_crypto_service_context) {
	        if (m_rpc_session_handle) {
                        service_context_close(m_crypto_service_context, m_rpc_session_handle);
                        m_rpc_session_handle = NULL;
	        }

                service_context_relinquish(m_crypto_service_context);
                m_crypto_service_context = NULL;
	}
    }

    psa_status_t generateVolatileEccKeyPair(std::vector<psa_key_id_t> &key_ids)
    {
        psa_status_t status;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&attributes, 521);

        psa_key_id_t key_id;
        status = m_crypto_client->generate_key(&attributes, &key_id);

        psa_reset_key_attributes(&attributes);

        if (status == PSA_SUCCESS) key_ids.push_back(key_id);

        return status;
    }

    psa_status_t generateVolatileRsaKeyPair(std::vector<psa_key_id_t> &key_ids)
    {
        psa_status_t status;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_CRYPT);
        psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
        psa_set_key_bits(&attributes, 512);

        psa_key_id_t key_id;
        status = m_crypto_client->generate_key(&attributes, &key_id);

        psa_reset_key_attributes(&attributes);

        if (status == PSA_SUCCESS) key_ids.push_back(key_id);

        return status;
    }

    psa_status_t destroyKeys(const std::vector<psa_key_id_t> &key_ids)
    {
        psa_status_t status = PSA_SUCCESS;
        size_t key_index = 0;

        while ((key_index < key_ids.size()) && (status == PSA_SUCCESS)) {

            status = m_crypto_client->destroy_key(key_ids[key_index]);
            ++key_index;
        }

        return status;
    }

    /*
     * Maximum number of key slots in mbedcrypto
     * is 32.  Some key slots may be used by provisioned
     * keys so allow a lower limit.
     */
    const size_t MAX_KEY_SLOTS = 30;

    rpc_session_handle m_rpc_session_handle;
    struct service_context *m_crypto_service_context;
    crypto_client *m_crypto_client;
};

TEST(CryptoServiceLimitTests, volatileEccKeyPairLimit)
{
    size_t expected_limit = MAX_KEY_SLOTS;
    size_t actual_limit = 0;
    std::vector<psa_key_id_t> key_ids;
    psa_status_t generate_status = PSA_SUCCESS;
    psa_status_t destroy_status;

    while (actual_limit < expected_limit) {

        generate_status = generateVolatileEccKeyPair(key_ids);

        if (generate_status == PSA_SUCCESS)
            ++actual_limit;
        else
            break;
    }

    destroy_status = destroyKeys(key_ids);

    CHECK_EQUAL(PSA_SUCCESS, generate_status);
    CHECK_EQUAL(PSA_SUCCESS, destroy_status);
    CHECK_EQUAL(expected_limit, actual_limit);
}

TEST(CryptoServiceLimitTests, volatileRsaKeyPairLimit)
{
    size_t expected_limit = MAX_KEY_SLOTS;
    size_t actual_limit = 0;
    std::vector<psa_key_id_t> key_ids;
    psa_status_t generate_status = PSA_SUCCESS;
    psa_status_t destroy_status;

    while (actual_limit < expected_limit) {

        generate_status = generateVolatileRsaKeyPair(key_ids);

        if (generate_status == PSA_SUCCESS)
            ++actual_limit;
        else
            break;
    }

    destroy_status = destroyKeys(key_ids);

    CHECK_EQUAL(PSA_SUCCESS, generate_status);
    CHECK_EQUAL(PSA_SUCCESS, destroy_status);
    CHECK_EQUAL(expected_limit, actual_limit);
}
