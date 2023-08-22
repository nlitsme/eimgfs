cmake_minimum_required(VERSION 3.10)
project(eimgfs)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_find")

include(boilerplate)
option(OPT_M32 "To enable the 32-bit build." OFF)


if (MSVC)
    add_definitions(-D_WIN32_WINNT_WIN10_TH2=1)
endif()

find_package(itslib REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED date_time)

add_executable(eimgfs eimgfs.cpp)
target_link_libraries(eimgfs PUBLIC itslib)
target_compile_definitions(eimgfs PUBLIC -D_NO_COMPRESS)
target_link_libraries(eimgfs PUBLIC OpenSSL::Crypto)
target_link_libraries(eimgfs PUBLIC Boost::headers Boost::date_time)
target_link_directories(eimgfs PUBLIC ${Boost_LIBRARY_DIRS})


if(OPT_M32)
add_library(dllloader32 STATIC dllloader/dllloader.cpp) 
if (NOT MSVC)
    target_compile_options(dllloader32 PUBLIC -m32)
    target_link_options(dllloader32 PUBLIC -m32)
endif()
target_include_directories(dllloader32 PUBLIC dllloader)
target_link_libraries(dllloader32 PUBLIC itslib)

add_library(computils32 INTERFACE) 
target_include_directories(computils32 INTERFACE CompressUtils)
if (NOT MSVC)
    target_compile_options(computils32 INTERFACE -m32)
endif()

add_executable(eimgfs32 eimgfs.cpp)
target_link_libraries(eimgfs32 PUBLIC itslib)
target_link_libraries(eimgfs32 PUBLIC dllloader32 computils32)
target_link_libraries(eimgfs32 PUBLIC OpenSSL::Crypto)
target_link_libraries(eimgfs32 PUBLIC Boost::headers Boost::date_time)
target_link_directories(eimgfs32 PUBLIC ${Boost_LIBRARY_DIRS})

endif()
