/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_MBEDTLS_USER_H
#define CONFIG_MBEDTLS_USER_H

/**
 * Mbed TLS configuration for building libmbedcrypto to act as a backend
 * for the crypto service provider running in an isolated secure processing
 * environment.  Note that supported crypto operations are configured
 * separately using the PSA crypto build interface (PSA_WANT_xxx). This
 * decouples Mbed TLS specific configuration from the more general crypto
 * capabilities configuration.
 */
#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_NO_UDBL_DIVISION
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_FS_IO
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_PLATFORM_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_PADLOCK_C

/* Enable owner labelling of key ids for partitioning the key store */
#define MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

/**
 * This provides an api namespace which enables a prefix to be added to
 * psa crypto api fuctions to make the mbedtls built realization distinct
 * from any other realizations within the same build.
 */
#define BACKEND_CRYPTO_API_ADD_PREFIX(f)    __mbedtls_backend_##f
#include "../prefixed_crypto_api.h"

#endif /* CONFIG_MBEDTLS_USER_H */
