#-------------------------------------------------------------------------------
# Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.16)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  The CMakeLists.txt for building the internal-trusted-storage deployment for opteesp
#
#  Builds the secure storage service provider for running in an SEL0 secure
#  partition hosted by OPTEE in the role of SPM.
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/opteesp/env.cmake)
project(trusted-services LANGUAGES C ASM)
add_executable(internal-trusted-storage)
target_include_directories(internal-trusted-storage PRIVATE "${TOP_LEVEL_INCLUDE_DIRS}")
set(SP_UUID "dc1eef48-b17a-4ccf-ac8b-dfcff7711b14")


# Include SP DEV KIT interface
set(SP_DEV_KIT_INC_DIR ${CMAKE_CURRENT_LIST_DIR})
list(APPEND CMAKE_MODULE_PATH "${TS_ROOT}/external/Spdevkit")
find_package(Spdevkit COMPONENTS SP_HEADER interface)

sp_dev_kit_configure_linking(TARGET internal-trusted-storage DEFINES ARM64=1)
target_link_libraries(internal-trusted-storage ${SP_DEV_KIT_LIBRARIES})

add_components(TARGET "internal-trusted-storage"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		components/messaging/ffa/libsp
		components/rpc/ffarpc/endpoint
		components/rpc/common/interface
		components/service/common
		components/service/common/provider
		components/service/secure_storage/frontend/secure_storage_provider
		components/service/secure_storage/backend/secure_flash_store
		components/service/secure_storage/backend/secure_flash_store/flash_fs
		components/service/secure_storage/backend/secure_flash_store/flash
		components/service/secure_storage/factory/common/sfs
		protocols/rpc/common/packed-c
		protocols/service/secure_storage/packed-c
		environments/opteesp
)

target_sources(internal-trusted-storage PRIVATE
	sp.c
)

target_compile_definitions(internal-trusted-storage PRIVATE
	ARM64=1
)

target_include_directories(internal-trusted-storage PRIVATE
	${TS_ROOT}
	${TS_ROOT}/components
	${TS_ROOT}/deployments/internal-trusted-storage/opteesp
)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	target_compile_options(internal-trusted-storage PRIVATE
		-fdiagnostics-show-option
		-fpic
		-gdwarf-2
		-mstrict-align
		-O0
		-std=gnu99
	)

	# Options for GCC that control linking
	target_link_options(internal-trusted-storage PRIVATE
		-e __sp_entry
		-fno-lto
		-nostdlib
		-pie
		-zmax-page-size=4096
	)
	# Options directly for LD, these are not understood by GCC
	target_link_options(internal-trusted-storage PRIVATE
		-Wl,--as-needed
		-Wl,--sort-section=alignment
		# -Wl,--dynamic-list ${CMAKE_CURRENT_LIST_DIR}/dyn_list
	)
endif()

compiler_generate_stripped_elf(TARGET internal-trusted-storage NAME "${SP_UUID}.stripped.elf" RES STRIPPED_ELF)

######################################## install
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install CACHE PATH "location to install build output to." FORCE)
endif()
install(TARGETS internal-trusted-storage
			PUBLIC_HEADER DESTINATION ${TS_ENV}/include
			RUNTIME DESTINATION ${TS_ENV}/bin
		)
install(FILES ${STRIPPED_ELF} DESTINATION ${TS_ENV}/bin)

set(EXPORT_SP_NAME "internal-trusted-storage")
set(EXPORT_SP_UUID ${SP_UUID})
include(${TS_ROOT}/environments/opteesp/ExportSp.cmake)