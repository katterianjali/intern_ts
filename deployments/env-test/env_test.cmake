#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  The base build file shared between deployments of 'env-test' for
#  different environments.  Used for running tests that validate hardwarw
#  backed services available from within a secure execution environment.
#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
#  Components that are common across all deployments
#
#-------------------------------------------------------------------------------
add_components(
	TARGET "env-test"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
	"components/common/tlv"
	"components/config/ramstore"
	"components/rpc/common/interface"
	"components/rpc/common/caller"
	"components/service/common/include"
	"components/service/common/provider"
	"components/service/test_runner/provider"
	"components/service/test_runner/provider/serializer/packed-c"
	"components/service/test_runner/provider/backend/null"
	"components/service/test_runner/provider/backend/simple_c"
	"components/service/crypto/provider/mbedcrypto"
	"components/service/crypto/provider/mbedcrypto/trng_adapter/platform"
	"components/service/crypto/provider/mbedcrypto/trng_adapter/test"
	"components/service/secure_storage/include"
	"components/service/secure_storage/frontend/psa/its"
	"components/service/secure_storage/backend/secure_storage_client"
	"protocols/rpc/common/packed-c"
)

#-------------------------------------------------------------------------------
#  Components used from external projects
#
#-------------------------------------------------------------------------------

# Mbed TLS provides libmbedcrypto
list(APPEND MBEDTLS_EXTRA_INCLUDES ${SP_DEV_KIT_INCLUDE_DIR})
set(MBEDTLS_EXTRA_INCLUDES ${MBEDTLS_EXTRA_INCLUDES}
	CACHE STRING "PSA ITS for Mbed TLS" FORCE)
include(${TS_ROOT}/external/MbedTLS/MbedTLS.cmake)
target_link_libraries(env-test PRIVATE mbedcrypto)
