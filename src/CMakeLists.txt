add_library(
    urc
    account.c
    bip8539.c
    jadeaccount.c
    jade_rpc.c
    eckey.c
    hdkey.c
    output.c
    psbt.c
    seed.c
    internals.h
    macros.h
    utils.c
    utils.h
    core.c
)
file(
    GLOB
    urc_headers
    ${CMAKE_SOURCE_DIR}/include/urc/crypto-*.h
    ${CMAKE_SOURCE_DIR}/include/urc/error.h
    ${CMAKE_SOURCE_DIR}/src/jade_bip8539.h
    ${CMAKE_SOURCE_DIR}/include/urc/tags.h
    ${CMAKE_SOURCE_DIR}/include/urc/urc.h
    ${CMAKE_SOURCE_DIR}/include/urc/core.h
)

target_sources(urc PRIVATE ${urc_headers})
target_link_libraries(urc PUBLIC PkgConfig::TinyCBOR PkgConfig::wallycore)
target_include_directories(
    urc PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include> $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
               $<INSTALL_INTERFACE:include>
)
set_target_properties(urc PROPERTIES PUBLIC_HEADER "${urc_headers}" C_STANDARD 11)
target_compile_options(urc PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(CMAKE_BUILD_TYPE STREQUAL Debug)
    target_compile_options(urc PRIVATE --coverage)
    target_link_options(urc PUBLIC --coverage)
endif()
