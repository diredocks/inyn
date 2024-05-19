cmake_minimum_required(VERSION 3.10)

# Define the project
project(inyn VERSION 1.3)

# Include directories for header files
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Find libcrypto package
find_package(PkgConfig REQUIRED)
pkg_check_modules(libcrypto REQUIRED IMPORTED_TARGET libcrypto)

# Find libpcap package
pkg_check_modules(libpcap REQUIRED libpcap)

# Define the executable and its source files
add_executable(inyn 
    main.c 
    auth.c 
    ip.c 
    fillmd5-libcrypto.c 
    #njit8021xclient.c 
    #md5-buildin/md5_one.c 
    #md5-buildin/md5_dgst.c 
    #md5-buildin/mem_clr.c 
    h3c_AES_MD5/aes.c 
    h3c_AES_MD5/h3c_AES_MD5.c
)

# Include directories
target_include_directories(inyn PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${libcrypto_INCLUDE_DIRS}
    ${libpcap_INCLUDE_DIRS}
)

# Compiler options and definitions
# If you have specific compiler options and definitions, set them here
#set(V_CCOPT "-Wall -Werror")
#set(V_DEFS "-DSOME_DEFINITION")
#set(V_INCLS "-I${CMAKE_CURRENT_SOURCE_DIR}/some_include_directory")

target_compile_options(inyn PRIVATE ${V_CCOPT})
target_compile_definitions(inyn PRIVATE ${V_DEFS})

# Link libraries
target_link_libraries(inyn PRIVATE 
    PkgConfig::libcrypto 
    ${libpcap_LIBRARIES}
    ${LBL_LIBS}
)

# Configure a header file to pass some of the CMake settings
#configure_file(config.h.in config.h)
target_include_directories(inyn PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
