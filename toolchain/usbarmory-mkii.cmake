# ===========================================================================
# This toolchain file assumes the following environment variables are preset:
# USBARMORY_CC = path to gcc binary
# USBARMORY_CXX = path to g++ binary
# USBARMORY_GCC_LIBC = path to gcc's libc directory
# USBARMORY_OPENSSL = path to openssl's root directory (existing build)
# ===========================================================================

# Define the toolchain
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Set the cross-compiling toolchain
set(CMAKE_C_COMPILER $ENV{USBARMORY_CC})
set(CMAKE_CXX_COMPILER $ENV{USBARMORY_CXX})

# Set the sysroot directory
set(CMAKE_SYSROOT $ENV{USBARMORY_GCC_LIBC})
set(CMAKE_C_IMPLICIT_LINK_DIRECTORIES ${CMAKE_SYSROOT}/usr/lib)
set(CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES ${CMAKE_SYSROOT}/usr/lib)

# Set the library search path
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)

# Set the header search path
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)

# Set the program search path
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM BOTH)

# Set our custom openssl directory
set(OPENSSL_ROOT_DIR $ENV{USBARMORY_OPENSSL})

set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_SYSROOT})