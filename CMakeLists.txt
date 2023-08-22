cmake_minimum_required(VERSION 3.18)

project(ur_c C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


option(FETCH_DEPS "tell cmake to go fetch dependencies itself" OFF)

### dependencies
include(cmake/dependencies.cmake)
if (FETCH_DEPS)
    fetch_tinycbor()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TinyCBOR REQUIRED IMPORTED_TARGET)
endif()

add_library(urc 
    include/urc/urc.h
    src/eckey.c include/urc/crypto_eckey.h
    src/hdkey.c include/urc/crypto_hdkey.h
    src/psbt.c include/urc/crypto_psbt.h
    src/seed.c include/urc/crypto_seed.h

    src/macros.h
    src/utils.c src/utils.h
    # src/p2pkh.c
    # src/output.c
)

target_link_libraries(urc PUBLIC PkgConfig::TinyCBOR)
target_include_directories(urc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)
set_target_properties(urc PROPERTIES C_STANDARD 11)
target_compile_options(urc PRIVATE -Wall -Wextra -Wpedantic -Werror)

if(NOT ENABLE_TESTS)
    return()
endif()

enable_testing()
if (FETCH_DEPS)
    fetch_unity()
else()
    find_package(unity REQUIRED)
endif()

add_executable(parser 
    tests/helpers.h tests/helpers.c

    tests/parser.c
)
target_link_libraries(parser PRIVATE urc unity)
target_include_directories(parser PRIVATE ${CMAKE_SOURCE_DIR}/src)

add_test(NAME parser COMMAND parser)
