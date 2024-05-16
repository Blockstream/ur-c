if(FETCH_DEPS)
    fetch_unity()
else()
    find_package(unity REQUIRED)
endif()

add_executable(
    units
    helpers.h
    helpers.c
    formatter.c
    parser.c
    psbt.c
    runner.c
    jade_rpc.c
)
target_link_libraries(units PRIVATE urc unity)
target_include_directories(units PRIVATE ${CMAKE_SOURCE_DIR}/src)
add_test(NAME units COMMAND units)

if(ENABLE_FUZZ_TESTS)
    add_executable(fuzzy_parser fuzzy/parser.c)
    target_link_libraries(fuzzy_parser PRIVATE urc)
    target_compile_options(fuzzy_parser PRIVATE "-fsanitize=fuzzer,address,undefined")
    target_link_options(fuzzy_parser PRIVATE "-fsanitize=fuzzer,address,undefined")
    add_test(NAME fuzzy_parser COMMAND fuzzy_parser -max_total_time=30)
endif()
