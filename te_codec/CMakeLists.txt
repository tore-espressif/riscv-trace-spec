cmake_minimum_required(VERSION 3.2)

project(riscv-trace-codec)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeModules)

set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
add_subdirectory(riscv-disassembler)
add_executable(riscv-trace-codec
    src/decoder-algorithm-public.c
    src/encoder-algorithm-public.c
    src/te-codec-utilities.c
    src/te-elf-dis.c
    src/te-memory.c
    esp_trace_decoder/esp_trace_decoder.c
    main.c
)
target_compile_definitions(riscv-trace-codec PUBLIC TE_WITH_STATISTICS)
target_compile_options(riscv-trace-codec PUBLIC -g)
target_link_libraries(riscv-trace-codec PUBLIC riscv-disassembler)
target_include_directories(riscv-trace-codec PUBLIC src esp_trace_decoder)

if(CMAKE_COMPILER_IS_GNUCXX)
    
    option(CODE_COVERAGE_VERBOSE ON)
    include(CodeCoverage)
    
    append_coverage_compiler_flags()

    # we need to turn off optimization for non-skewed coverage reports
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -O0")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")

    setup_target_for_coverage_gcovr_html(
            NAME coverage
            #EXECUTABLE riscv-trace-codec -e ../test_trace.elf ../trace_dump/trace_exception_out.hex ../trace_dump/trace_func_ptrs_out.hex ../trace_dump/trace_interrupt_out.hex ../trace_dump/trace_nested_calls_out.hex ../trace_dump/trace_start_stop_out.hex ../trace_dump/trace_branches_out.hex ../trace_dump/trace_sequential_jump_out.hex ../trace_dump/trace_loops_out.hex ../trace_dump/trace_loops_longer_sync_out.hex
            EXECUTABLE riscv-trace-codec -e ../test_trace.elf ../trace_dump/trace_qual_status_out.hex
            BASE_DIRECTORY "../"
            DEPENDENCIES riscv-trace-codec
    )
endif()