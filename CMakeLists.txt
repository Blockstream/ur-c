cmake_minimum_required(VERSION 3.16)

project(urc
    VERSION 0.0.2
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
    pkg_check_modules(TinyCBOR REQUIRED IMPORTED_TARGET tinycbor)
endif()

add_library(urc 
    include/urc/urc.h

    src/account.c include/urc/crypto_account.h
    src/jadeaccount.c
    src/eckey.c include/urc/crypto_eckey.h
    src/hdkey.c include/urc/crypto_hdkey.h
    src/output.c include/urc/crypto_output.h
    src/psbt.c include/urc/crypto_psbt.h
    src/seed.c include/urc/crypto_seed.h
    src/bip8539.c include/urc/jade_bip8539.h

    src/internals.h
    src/macros.h
    src/utils.c src/utils.h
)
set(urc_headers
    ${CMAKE_SOURCE_DIR}/include/urc/urc.h
    ${CMAKE_SOURCE_DIR}/include/urc/error.h
    ${CMAKE_SOURCE_DIR}/include/urc/tags.h
    ${CMAKE_SOURCE_DIR}/include/urc/crypto_account.h
    ${CMAKE_SOURCE_DIR}/include/urc/crypto_eckey.h
    ${CMAKE_SOURCE_DIR}/include/urc/crypto_hdkey.h
    ${CMAKE_SOURCE_DIR}/include/urc/crypto_output.h
    ${CMAKE_SOURCE_DIR}/include/urc/crypto_psbt.h
    ${CMAKE_SOURCE_DIR}/include/urc/crypto_seed.h
    ${CMAKE_SOURCE_DIR}/include/urc/jade_bip8539.h
)

target_link_libraries(urc PUBLIC PkgConfig::TinyCBOR)
target_include_directories(urc PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)
set_target_properties(urc PROPERTIES
    PUBLIC_HEADER "${urc_headers}"
    C_STANDARD 11
)
target_compile_options(urc PRIVATE -Wall -Wextra -Wpedantic -Werror)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
set(INSTALL_LIBDIR ${CMAKE_INSTALL_LIBDIR})
configure_package_config_file(cmake/urc-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/urc-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/urc
    PATH_VARS INSTALL_LIBDIR
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/urc-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/urc-config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/urc-config-version.cmake
              DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/urc )
install(TARGETS urc
    EXPORT "urc-target"
    RUNTIME EXCLUDE_FROM_ALL
    OBJECTS EXCLUDE_FROM_ALL
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/urc
)
install(EXPORT "urc-target"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/urc
    NAMESPACE ${PROJECT_NAME}::
    FILE "urc-targets.cmake"
)

if(NOT ENABLE_TESTS)
    return()
endif()

enable_testing()
if (FETCH_DEPS)
    fetch_unity()
else()
    find_package(unity REQUIRED)
endif()

add_executable(units
    tests/helpers.h tests/helpers.c

    tests/parser.c tests/formatter.c
    tests/runner.c
)
target_link_libraries(units PRIVATE urc unity)
target_include_directories(units PRIVATE ${CMAKE_SOURCE_DIR}/src)

add_test(NAME units COMMAND units)
