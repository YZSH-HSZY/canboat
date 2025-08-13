cmake_minimum_required(VERSION 3.16)

project(canboat LANGUAGES C)

set(COMMON_SOURCES 
    common/b64.c
    common/common.c
    common/parse.c
    common/utf.c
)

set(COMMON_HEADERS
    common/common.h
    common/dup.h
    common/license.h
    common/parse.h
    common/pow.h
    common/serial.h
    common/utf.h
    common/version.h
)

add_library(common STATIC ${COMMON_SOURCES} ${COMMON_HEADERS})
target_include_directories(common PRIVATE . common)

set(ACTISENSE-SERIAL_SOURCES
    actisense-serial/actisense-serial.c
    actisense-serial/actisense.h
)

add_executable(actisense-serial ${ACTISENSE-SERIAL_SOURCES})
target_link_libraries(actisense-serial common)
target_include_directories(actisense-serial PRIVATE common)

set(PRINT_UDP_SOURCES
    print_udp/print_udp.c
)

add_executable(print_udp ${PRINT_UDP_SOURCES})
target_link_libraries(print_udp common)
target_include_directories(print_udp PRIVATE common)
# target_include_directories(print_udp PUBLIC analyzer)

