#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

add_components(TARGET "se-proxy"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		"components/common/fdt"
		"components/common/trace"
		"components/common/utils"
		"protocols/rpc/common/packed-c"
		"protocols/service/secure_storage/packed-c"
		"protocols/service/crypto/protobuf"
		"components/common/tlv"
		"components/config/ramstore"
		"components/config/loader/sp"
		"components/messaging/ffa/libsp"
		"components/rpc/ffarpc/endpoint"
		"components/rpc/common/interface"
		"components/rpc/common/demux"
		"components/service/common/include"
		"components/service/common/serializer/protobuf"
		"components/service/common/client"
		"components/service/common/provider"
		"components/service/discovery/provider"
		"components/service/discovery/provider/serializer/packed-c"
		"components/service/crypto/include"
		"components/service/crypto/provider"
		"components/service/crypto/provider/serializer/protobuf"
		"components/service/crypto/provider/serializer/packed-c"
		"components/service/crypto/provider/extension/hash"
		"components/service/crypto/provider/extension/hash/serializer/packed-c"
		"components/service/crypto/provider/extension/cipher"
		"components/service/crypto/provider/extension/cipher/serializer/packed-c"
		"components/service/crypto/provider/extension/key_derivation"
		"components/service/crypto/provider/extension/key_derivation/serializer/packed-c"
		"components/service/crypto/provider/extension/mac"
		"components/service/crypto/provider/extension/mac/serializer/packed-c"
		"components/service/crypto/provider/extension/aead"
		"components/service/crypto/provider/extension/aead/serializer/packed-c"
		"components/service/crypto/factory/full"
		"components/service/secure_storage/include"
		"components/service/secure_storage/frontend/secure_storage_provider"
		"components/service/attestation/include"
		"components/service/attestation/provider"
		"components/service/attestation/provider/serializer/packed-c"

		# Stub service provider backends
		"components/rpc/dummy"
		"components/rpc/common/caller"
		"components/service/attestation/reporter/stub"
		"components/service/attestation/key_mngr/stub"
		"components/service/crypto/backend/stub"
		"components/service/crypto/client/psa"
		"components/service/secure_storage/backend/mock_store"
)

target_sources(se-proxy PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/common/se_proxy_sp.c
	${CMAKE_CURRENT_LIST_DIR}/common/service_proxy_factory.c
)

#-------------------------------------------------------------------------------
#  Components used from external projects
#
#-------------------------------------------------------------------------------

# Get libc include dir
get_property(LIBC_INCLUDE_PATH TARGET stdlib::c PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
get_property(LIBC_SYSTEM_INCLUDE_PATH TARGET stdlib::c PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES)

# Nanopb
list(APPEND NANOPB_EXTERNAL_INCLUDE_PATHS ${LIBC_INCLUDE_PATH})
list(APPEND NANOPB_EXTERNAL_SYSTEM_INCLUDE_PATHS ${LIBC_SYSTEM_INCLUDE_PATH})
include(../../../external/nanopb/nanopb.cmake)
target_link_libraries(se-proxy PRIVATE nanopb::protobuf-nanopb-static)
protobuf_generate_all(TGT "se-proxy" NAMESPACE "protobuf" BASE_DIR "${TS_ROOT}/protocols")

#################################################################

target_include_directories(se-proxy PRIVATE
	${TS_ROOT}
	${TS_ROOT}/components
)
