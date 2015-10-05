cmake_minimum_required(VERSION 2.8)

project(TaintChecker CXX)
set(TAINTCHECKER_VERSION "1.0")

set(CPACK_PACKAGE_NAME "taintchecker")
set(CPACK_PACKAGE_CONTACT "Francisco Chiotta")
set(CPACK_PACKAGE_VENDOR ${CPACK_PACKAGE_CONTACT})
set(CPACK_PACKAGE_VERSION ${TAINTCHECKER_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A plugin for Clang compiler which carries out tainting analysis.")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_RPM_PACKAGE_RELEASE "1%{?dist}")
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3") 
set(CPACK_RPM_PACKAGE_GROUP "Development/Tools")
set(CPACK_RPM_PACKAGE_URL "https://github.com/franchiotta/taintchecker")
set(CPACK_RPM_PACKAGE_DESCRIPTION "TaintChecker implements tainting analysis.")
set(CMAKE_MACOSX_RPATH 1)
include(CPack)

if(NOT DEFINED LLVM_PATH)
	message(FATAL_ERROR "Variable 'LLVM_PATH' is mandatory. Provide it with the path of a llvm build directory.")
endif(NOT DEFINED LLVM_PATH)


set(LLVM_BIN ${LLVM_PATH}/bin)
set(LLVM_DEBUG_BIN ${LLVM_PATH}/Debug/bin)

#
#install(FILES README.md
#  DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Clang REQUIRED)
find_package(XML REQUIRED)

add_subdirectory(src)