message(STATUS "cmake uses xml2-config to check if you have installed libxml2 in your system. If you don't, the building will be abort.")

execute_process(COMMAND xml2-config --cflags
				OUTPUT_VARIABLE LIBXML_INCLUDE_FLAGS
				RESULT_VARIABLE RESULT_LIBXML_INCLUDE_FLAGS)

execute_process(COMMAND xml2-config --libs
				OUTPUT_VARIABLE LIBXML_LINK_FLAGS
				RESULT_VARIABLE RESULT_LIBXML_LINK_FLAGS)

if(NOT ${RESULT_LIBXML_INCLUDE_FLAGS} MATCHES "0" OR
	NOT ${RESULT_LIBXML_LINK_FLAGS} MATCHES "0")
  message(FATAL_ERROR "Can't found program: xml2-config.")   
endif()

# Removes leadng and trailing spaces
string(STRIP ${LIBXML_INCLUDE_FLAGS} LIBXML_INCLUDE_FLAGS)
string(STRIP ${LIBXML_LINK_FLAGS} LIBXML_LINK_FLAGS)

message(STATUS "libxml include directories:  ${LIBXML_INCLUDE_FLAGS}")
message(STATUS "libxml link flags:  ${LIBXML_LINK_FLAGS}")