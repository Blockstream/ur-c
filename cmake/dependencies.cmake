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
