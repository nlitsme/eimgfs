cmake_minimum_required(VERSION 3.10)
project(eimgfs)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_find")

include(boilerplate)

option(OPT_M32  "To build the 32-bit version."  OFF)


if (MSVC)
    add_definitions(-D_WIN32_WINNT_WIN10_TH2=1)
endif()
if (OPT_M32)
    if (NOT MSVC)
        add_compile_options("-m32")
        add_link_options("-m32")
    endif()
else()
    add_definitions(-D_NO_COMPRESS)
endif()


find_package(itslib REQUIRED)

if (OPT_M32)
    add_library(dllloader STATIC dllloader/dllloader.cpp) 
    if (NOT MSVC)
        set_target_properties(dllloader PROPERTIES COMPILE_OPTIONS "-m32" LINK_FLAGS "-m32")
    endif()
    target_include_directories(dllloader PUBLIC dllloader)
    target_link_libraries(dllloader PUBLIC itslib)

    add_library(computils INTERFACE) 
    target_include_directories(computils INTERFACE CompressUtils)
endif()

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED date_time)

add_executable(eimgfs eimgfs.cpp)
target_link_libraries(eimgfs  itslib)
if (OPT_M32)
    target_link_libraries(eimgfs  dllloader computils)
endif()
target_link_libraries(eimgfs OpenSSL::Crypto)
target_link_libraries(eimgfs Boost::headers Boost::date_time)
target_link_directories(eimgfs PUBLIC ${Boost_LIBRARY_DIRS})

