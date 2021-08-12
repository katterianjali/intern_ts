/*
 * Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CONFIG_MBEDTLS_USER_H
#define CONFIG_MBEDTLS_USER_H

/* Mbed TLS configuration for using libmbedcrypto in
 * a Posix environment.  Supported crypto operations
 * are configured separately via the PSA crypto build
 * interface (PSA_WANT_xxx).
 */
#define MBEDTLS_PSA_CRYPTO_CONFIG
#define MBEDTLS_NO_UDBL_DIVISION
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_FS_IO
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_AESNI_C
#undef MBEDTLS_PADLOCK_C
#undef MBEDTLS_PLATFORM_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_TIMING_C

#endif /* CONFIG_MBEDTLS_USER_H */
