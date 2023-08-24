cmake_minimum_required(VERSION 3.18)

project(ur_c
    VERSION 0.0.1
    LANGUAGES C CXX
)
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
    include/ur-c/urc.h

    src/account.c include/ur-c/crypto_account.h
    src/eckey.c include/ur-c/crypto_eckey.h
    src/hdkey.c include/ur-c/crypto_hdkey.h
    src/output.c include/ur-c/crypto_output.h
    src/psbt.c include/ur-c/crypto_psbt.h
    src/seed.c include/ur-c/crypto_seed.h

    src/internals.h
    src/macros.h
    src/utils.c src/utils.h
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
