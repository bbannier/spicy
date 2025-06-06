# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

##### Compiler library.

set(AUTOGEN_H "${PROJECT_BINARY_DIR}/include/spicy/autogen")
set(AUTOGEN_CC "${PROJECT_BINARY_DIR}/spicy/src/autogen")
file(MAKE_DIRECTORY "${AUTOGEN_H}" "${AUTOGEN_CC}")
file(MAKE_DIRECTORY "${PROJECT_BINARY_DIR}/bin" "${PROJECT_BINARY_DIR}/lib")

set(AUTOGEN_H_HILTI "${PROJECT_BINARY_DIR}/include/hilti/autogen")

flex_target(scanner_spicy src/compiler/parser/scanner.ll ${AUTOGEN_CC}/__scanner.cc
            DEFINES_FILE ${AUTOGEN_CC}/__scanner.h)
bison_target_pp(parser_spicy src/compiler/parser/parser.yy ${AUTOGEN_CC}/__parser.cc DEFINES_FILE
                ${AUTOGEN_CC}/__parser.h)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.27")
    set_source_files_properties(${FLEX_scanner_spicy_OUTPUTS} PROPERTIES SKIP_LINTING ON)
    set_source_files_properties(${BISON_parser_spicy_OUTPUTS} PROPERTIES SKIP_LINTING ON)
endif ()

flex_bison_source(src/compiler/plugin.cc ${AUTOGEN_CC})
flex_bison_source(src/compiler/parser/driver.cc ${AUTOGEN_CC})
flex_bison_source(${AUTOGEN_CC}/__scanner.cc ${AUTOGEN_CC})
flex_bison_source(${AUTOGEN_CC}/__parser.cc ${AUTOGEN_CC})

set(SOURCES_COMPILER
    src/ast/builder/builder.cc
    src/ast/hook.cc
    src/ast/operators/unit.cc
    src/ast/operators/sink.cc
    src/ast/types/unit.cc
    src/ast/types/unit-items/field.cc
    src/ast/types/unit-items/switch.cc
    src/compiler/codegen/codegen.cc
    src/compiler/codegen/grammar.cc
    src/compiler/codegen/grammar-builder.cc
    src/compiler/codegen/parser-builder.cc
    src/compiler/codegen/parsers/literals.cc
    src/compiler/codegen/parsers/types.cc
    src/compiler/codegen/production.cc
    src/compiler/codegen/productions/look-ahead.cc
    src/compiler/codegen/productions/switch.cc
    src/compiler/codegen/productions/while.cc
    src/compiler/codegen/unit-builder.cc
    src/compiler/coercer.cc
    src/compiler/driver.cc
    src/compiler/init.cc
    src/compiler/parser/driver.cc
    src/compiler/plugin.cc
    src/compiler/printer.cc
    src/compiler/resolver.cc
    src/compiler/scope-builder.cc
    src/compiler/type-unifier.cc
    src/compiler/validator.cc
    ${SOURCES_OPERATORS}
    ${AUTOGEN_CC}/config.cc
    ${BISON_parser_spicy_OUTPUTS}
    ${FLEX_scanner_spicy_OUTPUTS})

add_library(spicy-objects OBJECT ${SOURCES_COMPILER})
set_property(TARGET spicy-objects PROPERTY POSITION_INDEPENDENT_CODE ON)
target_compile_options(spicy-objects PRIVATE "-Wall")
target_compile_options(spicy-objects PRIVATE $<$<CONFIG:Debug>:-O0>)
target_include_directories(spicy-objects BEFORE
                           PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_include_directories(spicy-objects BEFORE
                           PUBLIC $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include>)
target_include_directories(spicy-objects BEFORE PUBLIC ${FLEX_INCLUDE_DIRS})

# Unclear why we need this: Without it, the generated Bison/Flex get a broken
# include path on some systems. (Seen on Ubuntu 19.10).
set_target_properties(spicy-objects PROPERTIES NO_SYSTEM_FROM_IMPORTED true)

target_link_libraries(spicy-objects
                      PUBLIC $<IF:$<CONFIG:Debug>,spicy-rt-debug-objects,spicy-rt-objects>)
target_link_libraries(spicy-objects PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
target_link_libraries(spicy-objects PRIVATE hilti)

add_library(spicy)
hilti_link_libraries_in_tree(spicy PUBLIC)
spicy_link_object_libraries_in_tree(spicy PUBLIC)

##### Configuration files

# Spicy library directories
set_config_val(
    SPICY_CONFIG_LIBRARY_DIRS
    "!INSTALL!${CMAKE_INSTALL_FULL_DATADIR}/spicy !BUILD!${PROJECT_SOURCE_DIR}/spicy/lib")

# Include directories
set_config_val(
    SPICY_CONFIG_RUNTIME_CXX_INCLUDE_DIRS
    "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${PROJECT_SOURCE_DIR}/spicy/runtime/include !BUILD!${PROJECT_BINARY_DIR}/include"
)
set_config_val(
    SPICY_CONFIG_TOOLCHAIN_CXX_INCLUDE_DIRS
    "!INSTALL!${CMAKE_INSTALL_FULL_INCLUDEDIR} !BUILD!${PROJECT_SOURCE_DIR}/spicy/toolchain/include !BUILD!${PROJECT_BINARY_DIR}/include"
)

# CXX flags
set_config_val(SPICY_CONFIG_RUNTIME_CXX_FLAGS_DEBUG "")
set_config_val(SPICY_CONFIG_RUNTIME_CXX_FLAGS_RELEASE "")

# Libraries
set_config_val(SPICY_CONFIG_RUNTIME_LIBRARIES_DEBUG "spicy-rt-debug z")
set_config_val(SPICY_CONFIG_RUNTIME_LIBRARIES_RELEASE "spicy-rt z")

# Library directories
set_config_val(SPICY_CONFIG_RUNTIME_CXX_LIBRARY_DIRS "")
set_config_val(SPICY_CONFIG_TOOLCHAIN_CXX_LIBRARY_DIRS "")

# LD flags
set_config_val(SPICY_CONFIG_RUNTIME_LD_FLAGS_DEBUG "")
set_config_val(SPICY_CONFIG_RUNTIME_LD_FLAGS_RELEASE "")

# Generate configurarion
configure_file(include/config.h.in ${AUTOGEN_H}/config.h)
configure_file(src/config.cc.in ${AUTOGEN_CC}/config.cc)

##### Binaries

add_executable(spicy-config bin/spicy-config.cc)
target_compile_options(spicy-config PRIVATE "-Wall")
spicy_link_executable_in_tree(spicy-config PRIVATE)

add_executable(spicyc bin/spicyc.cc)
target_compile_options(spicyc PRIVATE "-Wall")
spicy_link_executable_in_tree(spicyc PRIVATE)

add_executable(spicy-driver bin/spicy-driver.cc)
target_compile_options(spicy-driver PRIVATE "-Wall")
spicy_link_executable_in_tree(spicy-driver PRIVATE)

add_executable(spicy-doc bin/spicy-doc.cc)
target_compile_options(spicy-doc PRIVATE "-Wall")
spicy_link_executable_in_tree(spicy-doc PRIVATE)

add_executable(spicy-batch-extract bin/spicy-batch-extract.cc)
target_compile_options(spicy-batch-extract PRIVATE "-Wall")
spicy_link_executable_in_tree(spicy-batch-extract PRIVATE)

add_subdirectory(bin/spicy-dump)

add_custom_target(spicy-build ALL DEPENDS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicy-build
                  COMMENT "Generating spicy-build")
add_custom_command(
    OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicy-build
    COMMENT "Copying spicy-build"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/bin/spicy-build
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/bin/spicy-build)

## Installation

install(TARGETS spicy LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS spicyc spicy-config spicy-driver RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(PROGRAMS ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/spicy-build DESTINATION ${CMAKE_INSTALL_BINDIR})

install_headers(include spicy)
install_headers(${PROJECT_BINARY_DIR}/include/spicy spicy)
install(CODE "file(REMOVE \"\$ENV\{DESTDIR\}${CMAKE_INSTALL_FULL_INCLUDEDIR}/spicy/spicy\")"
)# Get rid of symlink.

## Tests

add_executable(spicy-toolchain-tests EXCLUDE_FROM_ALL tests/main.cc tests/grammar.cc)
spicy_link_executable_in_tree(spicy-toolchain-tests PRIVATE)
target_link_libraries(spicy-toolchain-tests PRIVATE doctest)
target_compile_options(spicy-toolchain-tests PRIVATE "-Wall")
add_test(NAME spicy-toolchain-tests COMMAND ${PROJECT_BINARY_DIR}/bin/spicy-toolchain-tests)
