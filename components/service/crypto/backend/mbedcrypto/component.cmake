#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
if (NOT DEFINED TGT)
	message(FATAL_ERROR "mandatory parameter TGT is not defined.")
endif()

target_sources(${TGT} PRIVATE
	"${CMAKE_CURRENT_LIST_DIR}/mbedcrypto_backend.c"
	)

# Force use of the mbed crypto configuration required by the crypto service
# provider.  This configuration includes enabling the use of the PSA ITS API
# for persistent key storage which is realised by the its client adapter
# for the secure storage service.
set(MBEDTLS_USER_CONFIG_FILE
	"${CMAKE_CURRENT_LIST_DIR}/config_mbedtls_user.h"
	CACHE STRING "Configuration file for Mbed TLS" FORCE)

set(MBEDTLS_EXTRA_INCLUDES
	"${TS_ROOT}/components/service/common/include"
	"${TS_ROOT}/components/service/secure_storage/include"
	CACHE STRING "PSA ITS for Mbed TLS" FORCE)

# Ensure that mbedtls user config file define is also included in the parent build
# context as it potentially effects mbedtls public header files.
target_compile_definitions(${TGT} PUBLIC
	MBEDTLS_USER_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}"
	)
