# CMakeLists.txt
#
# Open vSwitch Netlink Dissector Plugin for Wireshark
# Out-of-tree plugin build
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.16)

project(OvsNetlink
	VERSION 0.1.0
	DESCRIPTION "Open vSwitch Netlink Dissector Plugin for Wireshark"
	LANGUAGES C
)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
		CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

# External plugins must define HAVE_SSIZE_T for the plugin toolchain.
include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
	VERSION=\"${PROJECT_VERSION}\"
	$<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

add_library(ovs_netlink MODULE
	src/plugin.c
	src/netlink-helpers.c
	src/packet-netlink-ovs_vport.c
	src/packet-netlink-ovs_datapath.c
	src/packet-netlink-ovs_flow.c
	src/packet-netlink-ovs_packet.c
	src/packet-netlink-ovs_meter.c
	src/packet-netlink-ovs_ct_limit.c
)
set_target_properties(ovs_netlink PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(ovs_netlink epan)

# Standard installation target
install(TARGETS ovs_netlink
	LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

# Convenience target: install plugin to the personal plugin directory
set(PERSONAL_PLUGIN_DIR "$ENV{HOME}/.local/lib/wireshark/plugins/${Wireshark_VERSION_MAJOR}.${Wireshark_VERSION_MINOR}/epan")
add_custom_target(copy_plugin
	COMMAND ${CMAKE_COMMAND} -E make_directory "${PERSONAL_PLUGIN_DIR}"
	COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ovs_netlink>
		"${PERSONAL_PLUGIN_DIR}"
	COMMENT "Installing plugin to: ${PERSONAL_PLUGIN_DIR}"
)

# Tests
enable_testing()
find_program(TSHARK_BIN tshark)
if(TSHARK_BIN)
	add_test(
		NAME dissectors
		COMMAND ${CMAKE_SOURCE_DIR}/tests/test-dissectors.sh
			${TSHARK_BIN}
			${CMAKE_SOURCE_DIR}/tests/ovs-netlink.pcap
	)
	# Ensure the plugin is built and installed before running tests
	set_tests_properties(dissectors PROPERTIES
		DEPENDS ovs_netlink
		ENVIRONMENT "WIRESHARK_PLUGIN_DIR=${Wireshark_PLUGIN_INSTALL_DIR}"
	)
else()
	message(STATUS "tshark not found, tests disabled")
endif()
