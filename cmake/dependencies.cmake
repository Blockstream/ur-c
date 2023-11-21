include(ExternalProject)
include(FetchContent)

macro(fetch_tinycbor)
    # tiny cbor
    ExternalProject_Add(
        TinyCBOR-external
        GIT_REPOSITORY https://github.com/intel/TinyCBOR
        GIT_TAG v0.6.0
        UPDATE_DISCONNECTED TRUE
        BUILD_IN_SOURCE TRUE
        BUILD_ALWAYS FALSE
        CONFIGURE_COMMAND ""
        BUILD_COMMAND make
        INSTALL_COMMAND make prefix="<INSTALL_DIR>" install
    )
    ExternalProject_Get_Property(TinyCBOR-external INSTALL_DIR INSTALL_DIR)
    add_library(PkgConfig::TinyCBOR STATIC IMPORTED)
    # otherwise cmake complains
    file(MAKE_DIRECTORY ${INSTALL_DIR}/include/tinycbor)

    set_target_properties(
        PkgConfig::TinyCBOR
        PROPERTIES IMPORTED_LOCATION ${INSTALL_DIR}/lib/libtinycbor.a # ugly but needed to mimick the pkg-config file
                   INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include/tinycbor
    )
    add_dependencies(PkgConfig::TinyCBOR TinyCBOR-external)
endmacro()

macro(fetch_wally)
    set(WALLY_DEBUG "--disable-debug")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(WALLY_DEBUG "--enable-debug")
    endif()
    ExternalProject_Add(
        wallycore-external
        GIT_REPOSITORY https://github.com/ElementsProject/libwally-core.git
        GIT_TAG release_1.0.0
        GIT_SUBMODULES src/secp256k1
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        BUILD_IN_SOURCE TRUE
        BUILD_ALWAYS FALSE
        CONFIGURE_COMMAND
            ./tools/autogen.sh && ./configure --prefix=<INSTALL_DIR> --disable-shared --enable-static --disable-tests
            --disable-swig-java --disable-swig-python ${WALLY_DEBUG}
        BUILD_COMMAND make
        INSTALL_COMMAND make install
    )
    ExternalProject_Get_Property(wallycore-external INSTALL_DIR INSTALL_DIR)
    # otherwise cmake complains
    file(MAKE_DIRECTORY ${INSTALL_DIR}/include/)

    add_library(PkgConfig::libsecp256k1 STATIC IMPORTED)
    set_target_properties(
        PkgConfig::libsecp256k1
        PROPERTIES IMPORTED_LOCATION ${INSTALL_DIR}/lib/libsecp256k1.a # ugly but needed to mimic the pkg-config file
                   INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include
    )
    add_dependencies(PkgConfig::libsecp256k1 wallycore-external)

    add_library(PkgConfig::wallycore STATIC IMPORTED)
    set_target_properties(
        PkgConfig::wallycore
        PROPERTIES IMPORTED_LOCATION ${INSTALL_DIR}/lib/libwallycore.a # ugly but needed to mimick the pkg-config file
                   INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include
    )
    add_dependencies(PkgConfig::wallycore wallycore-external PkgConfig::libsecp256k1)
    target_link_libraries(PkgConfig::wallycore INTERFACE PkgConfig::libsecp256k1)
endmacro()

macro(fetch_unity)
    FetchContent_Declare(
        Unity
        GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
        GIT_TAG v2.5.2
    )
    set(UNITY_EXTENSION_FIXTURE
        ON
        CACHE INTERNAL "Add fixture extension to unity"
    )
    FetchContent_MakeAvailable(Unity)

endmacro()
