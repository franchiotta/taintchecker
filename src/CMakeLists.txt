cmake_minimum_required(VERSION 2.8)
include(GNUInstallDirs)

# Including directories
include_directories(${CLANG_INCLUDE_DIRS})
include_directories(${CMAKE_BINARY_DIR}/src/includes)

# Adding some definitions
add_definitions(${CLANG_DEFINITIONS})
add_definitions(-std=c++11)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
add_library(CustomTaintChecker SHARED
	CustomTaintChecker.cpp
	TaintParser.cpp
	TaintUtil.cpp
	TaintVisitor.cpp
)

# Define taint checker compile flags.
set (TC_COMPILE_FLAGS "-fPIC -Wno-format-security ${LIBXML_INCLUDE_FLAGS}")

# Define taint checker link flags.
set (TC_LINK_FLAGS ${LIBXML_LINK_FLAGS})
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set (TC_LINK_FLAGS  "-Wl -undefined dynamic_lookup ${TC_LINK_FLAGS}")
endif()

set_target_properties(CustomTaintChecker PROPERTIES
    LINKER_LANGUAGE CXX
    COMPILE_FLAGS ${TC_COMPILE_FLAGS}
    SOVERSION 1.0)

target_link_libraries(CustomTaintChecker ${TC_LINK_FLAGS})

# Installing clang static analyzer library
install(TARGETS CustomTaintChecker
    LIBRARY DESTINATION ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})

# Copying example folder
add_custom_command(TARGET CustomTaintChecker PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/examples
    ${CMAKE_BINARY_DIR}/examples)

# Copying schema folder
add_custom_command(TARGET CustomTaintChecker PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/schemas
    ${CMAKE_BINARY_DIR}/schemas)


# Setting the schema file location.
set(SCHEMA_FILE ${CMAKE_BINARY_DIR}/schemas/taint-rules.xsd)

configure_file(
  ${CMAKE_SOURCE_DIR}/src/includes/TaintConfig.h.cmake
  ${CMAKE_BINARY_DIR}/src/includes/TaintConfig.h)
