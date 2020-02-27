cmake_minimum_required(VERSION 3.10)

project(pcap_eval
	DESCRIPTION "Evaluate TCP/UDP performance from PCAP files"
	LANGUAGES C CXX)

# Use C11 and CXX11
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

# Enable compiler warnings
if (CMAKE_C_COMPILER_ID MATCHES GNU OR CMAKE_C_COMPILER_ID MATCHES CLANG)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
endif()

# Add source to module path so the Findns3.cmake module will be found
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

find_package(PCAP REQUIRED)

add_executable(pcap_eval
		pcap_eval.cc)

target_link_libraries(pcap_eval pcap::pcap)
