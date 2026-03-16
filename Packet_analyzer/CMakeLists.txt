cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Source files
set(SOURCES
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Create the executable
add_executable(dpi_engine ${SOURCES})

# Link libpcap
if(WIN32)
    target_link_libraries(dpi_engine wpcap iphlpapi ws2_32)
else()
    target_link_libraries(dpi_engine pcap)
endif()
