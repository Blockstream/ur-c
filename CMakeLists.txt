cmake_minimum_required(VERSION 3.20)

project(example-cbor C CXX)
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

add_library(bcr 
    src/bcr.c include/bcr/bcr.h
    src/parser.c src/parser.h
    src/macros.h
)

target_link_libraries(bcr PUBLIC PkgConfig::TinyCBOR)
target_include_directories(bcr PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)
set_target_properties(bcr PROPERTIES C_STANDARD 11)

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
target_link_libraries(parser PRIVATE bcr unity)
target_include_directories(parser PRIVATE ${CMAKE_SOURCE_DIR}/src)

add_test(NAME parser COMMAND parser)
