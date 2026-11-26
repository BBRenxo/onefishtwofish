cmake_minimum_required(VERSION 3.20)
project(eac_reversal_suite LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(eac_inspector
    src/main.cpp
    src/pe_image.cpp
    src/sig_scanner.cpp
    src/protocol_decoders.cpp
    src/wdk_sandbox.cpp
)

target_include_directories(eac_inspector PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

if(MSVC)
    target_compile_options(eac_inspector PRIVATE /W4 /O2 /EHsc /utf-8)
else()
    target_compile_options(eac_inspector PRIVATE -Wall -Wextra -O2)
    if(MINGW)
        target_link_options(eac_inspector PRIVATE -static -static-libgcc -static-libstdc++)
    endif()
endif()
