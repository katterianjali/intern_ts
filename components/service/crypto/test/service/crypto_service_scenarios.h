/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <service/crypto/client/cpp/crypto_client.h>

/*
 * Service-level test scenarios for the crypto service that may be reused using
 * different concrete crypto_clients to check end-to-end operation using different
 * protocol serialization schemes.
 */
class crypto_service_scenarios
{
public:
    crypto_service_scenarios(crypto_client *crypto_client);
    ~crypto_service_scenarios();

    void generateRandomNumbers();
    void asymEncryptDecrypt();
    void asymEncryptDecryptWithSalt();
    void signAndVerifyHash();
    void signAndVerifyEat();
    void exportAndImportKeyPair();
    void exportPublicKey();
    void generatePersistentKeys();
    void generateVolatileKeys();
    void calculateHash();

private:
    crypto_client *m_crypto_client;
};
