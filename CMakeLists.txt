cmake_minimum_required(VERSION 3.16)

project(urc
    VERSION 0.3.0
    LANGUAGES C
)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(URC_FETCH_DEPS "tell cmake to go fetch dependencies itself" OFF)
option(URC_ENABLE_TESTS "enable tests" OFF)
option(URC_ENABLE_FUZZ_TESTS "enable fuzzy tests" OFF)
option(URC_ENABLE_COVERAGE "enable code coverage" OFF)
option(URC_ENABLE_VALGRIND "enable valgrind tests" OFF)

### dependencies
include(cmake/dependencies.cmake)
if (URC_FETCH_DEPS)
    fetch_tinycbor()
    fetch_wally()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TinyCBOR REQUIRED IMPORTED_TARGET tinycbor)
    pkg_check_modules(wallycore REQUIRED IMPORTED_TARGET wallycore)
    pkg_check_modules(libsecp256k1 REQUIRED IMPORTED_TARGET libsecp256k1)
endif()

add_subdirectory(src)

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

if(NOT URC_ENABLE_TESTS)
    return()
endif()

include(CTest)
add_subdirectory(tests)
