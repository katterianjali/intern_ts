/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <service/crypto/factory/crypto_provider_factory.h>
#include <service/crypto/provider/crypto_provider.h>
#include <service/crypto/provider/serializer/protobuf/pb_crypto_provider_serializer.h>
#include <service/crypto/provider/serializer/packed-c/packedc_crypto_provider_serializer.h>
#include <service/crypto/provider/extension/hash/hash_provider.h>
#include <service/crypto/provider/extension/hash/serializer/packed-c/packedc_hash_provider_serializer.h>

/**
 * A crypto provider factory that constucts a full-featured
 * crypto provider that is extended to support the full set of crypto
 * operations.  This factory is only capable of constructing
 * a single service provider instance.
 */

static struct default_crypto_provider
{
	struct crypto_provider crypto_provider;
	struct hash_provider hash_provider;

} instance;

struct crypto_provider *crypto_provider_factory_create(void)
{
	/* Initialize the base crypto provider */
	crypto_provider_init(&instance.crypto_provider);

	crypto_provider_register_serializer(&instance.crypto_provider,
		TS_RPC_ENCODING_PROTOBUF, pb_crypto_provider_serializer_instance());

	crypto_provider_register_serializer(&instance.crypto_provider,
		TS_RPC_ENCODING_PACKED_C, packedc_crypto_provider_serializer_instance());

	/* Extend with hash operations */
	hash_provider_init(&instance.hash_provider);

	hash_provider_register_serializer(&instance.hash_provider,
		TS_RPC_ENCODING_PACKED_C, packedc_hash_provider_serializer_instance());

	crypto_provider_extend(&instance.crypto_provider, &instance.hash_provider.base_provider);

	return &instance.crypto_provider;
}

/**
 * \brief Destroys a created crypto provider
 *
 * \param[in] provider    The crypto provider to destroy
  */
void crypto_provider_factory_destroy(struct crypto_provider *provider)
{
	(void)provider;
	crypto_provider_deinit(&instance.crypto_provider);
	hash_provider_deinit(&instance.hash_provider);
}
