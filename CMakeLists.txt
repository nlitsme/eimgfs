cmake_minimum_required(VERSION 3.10)
project(eimgfs)
set(CMAKE_CXX_STANDARD 17)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(OPT_M32  "To build the 32-bit version."  OFF)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(DARWIN TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
endif()


# checking if we are called in the correct way:
#  with a -B argument.  and without a cache file in the source directory.
if (CMAKE_CACHEFILE_DIR STREQUAL "${CMAKE_SOURCE_DIR}")
    message(FATAL_ERROR "\nUnexpected CMakeCache.txt file in the source directory. Please remove it.")
    return()
endif()

if (EXISTS ${CMAKE_BINARY_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "\nRun cmake with an explicit -B buildpath")
    return()
endif()

if(MSVC)
    # /MP = multithreaded build
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
    # /utf-8 = utf8 source and execution
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
endif()

if (WIN32)
    add_definitions(-DNOMINMAX -DNOGDI)
    add_definitions(-D_WIN32_WINNT_WIN10_TH2=1)
endif()
if (OPT_M32)
    add_compile_options("-m32")
    add_link_options("-m32")
else()
    add_definitions(-D_NO_COMPRESS)
endif()


add_library(itslib STATIC itslib/src/stringutils.cpp)
target_include_directories(itslib PUBLIC itslib/include)
target_compile_definitions(itslib PUBLIC _UNIX _NO_RAPI _NO_WINDOWS)

if (OPT_M32)
    add_library(dllloader STATIC dllloader/dllloader.cpp) 
    set_target_properties(dllloader PROPERTIES COMPILE_OPTIONS "-m32" LINK_FLAGS "-m32")
    target_include_directories(dllloader PUBLIC dllloader)
    target_link_libraries(dllloader PUBLIC itslib)

    add_library(computils INTERFACE) 
    target_include_directories(computils INTERFACE CompressUtils)
endif()

find_package(OpenSSL REQUIRED)

add_executable(eimgfs eimgfs.cpp)
target_link_libraries(eimgfs  itslib)
if (OPT_M32)
    target_link_libraries(eimgfs  dllloader computils)
endif()
target_link_libraries(eimgfs  OpenSSL::Crypto)

