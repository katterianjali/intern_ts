#-------------------------------------------------------------------------------
# Copyright (c) 2020, Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.16)
include(../../deployment.cmake REQUIRED)

#-------------------------------------------------------------------------------
#  The CMakeLists.txt for building the libsp deployment for opteesp
#
#  Used for building the libsp library that provides FFA related functons
#  for applications deployed in a secure partition.
#-------------------------------------------------------------------------------
include(${TS_ROOT}/environments/opteesp/env.cmake)

file(READ "${CMAKE_CURRENT_LIST_DIR}/version.txt" LIBSP_VERSION)
project(trusted-services
			VERSION
				${LIBSP_VERSION}
			 LANGUAGES
				C ASM
		)

add_library(sp STATIC)

# Include SP DEV KIT interface
set(SP_DEV_KIT_INC_DIR ${CMAKE_CURRENT_LIST_DIR})
list(APPEND CMAKE_MODULE_PATH "${TS_ROOT}/external/Spdevkit")
find_package(Spdevkit COMPONENTS interface)

target_link_libraries(sp PUBLIC ${SP_DEV_KIT_LIBRARIES})


add_components(TARGET "sp"
	BASE_DIR ${TS_ROOT}
	COMPONENTS
		components/messaging/ffa/libsp
		components/common/utils
)

target_compile_definitions("sp" PRIVATE
	ARM64=1
)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	target_compile_options("sp" PRIVATE
		-fdiagnostics-show-option
		-fpic
		-gdwarf-2
		-mstrict-align
		-O0
		-std=gnu99
	)
endif()

######################################## install
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install CACHE PATH "location to install build output to." FORCE)
endif()

install(
	TARGETS
		sp
	EXPORT
		LibspTargets
	ARCHIVE	DESTINATION
		lib
	PUBLIC_HEADER DESTINATION
		include
	COMPONENT
		libsp
)

#These would install the spdevkit content.
#install(FILES $<TARGET_PROPERTY:sp_devkit_ifc,INTERFACE_LINK_LIBRARIES> DESTINATION lib)
#install(FILES $<TARGET_PROPERTY:sp_devkit_ifc,INTERFACE_INCLUDE_DIRECTORIES>/ DESTINATION include)
### Create a config file package.
set(ConfigPackageLocation lib/cmake/libsp)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/LibspConfigVersion.cmake"
	VERSION "1.0.0"
	COMPATIBILITY SameMajorVersion
)

# Create targets file.
export(
	EXPORT
		LibspTargets
	FILE
		"${CMAKE_CURRENT_BINARY_DIR}/LibspTargets.cmake"
	NAMESPACE
		libsp::
)

# Finalize config file.
configure_package_config_file(
		LibspConfig.cmake.in
		"${CMAKE_CURRENT_BINARY_DIR}/LibspConfig.cmake"
	PATH_VARS

	INSTALL_DESTINATION
		${ConfigPackageLocation}
)

install(
	EXPORT
		LibspTargets
	FILE
		LibspTargets.cmake
	NAMESPACE
		libsp::
	DESTINATION
		${ConfigPackageLocation}
	COMPONENT
		libsp
)

# install config and version files
install(
	FILES
		"${CMAKE_CURRENT_BINARY_DIR}/LibspConfig.cmake"
		"${CMAKE_CURRENT_BINARY_DIR}/LibspConfigVersion.cmake"
		"${TS_ROOT}/external/Spdevkit/FindSpdevkit.cmake"
	DESTINATION
		${ConfigPackageLocation}
	COMPONENT
		libsp
)