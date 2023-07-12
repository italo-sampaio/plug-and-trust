# Define the toolchain
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# Set the cross-compiling toolchain
set(CMAKE_C_COMPILER /opt/gcc-linaro-10.2.1-2021.01-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER /opt/gcc-linaro-10.2.1-2021.01-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf-g++)

# Set the sysroot directory
set(CMAKE_SYSROOT /opt/gcc-linaro-10.2.1-2021.01-x86_64_arm-linux-gnueabihf/arm-linux-gnueabihf/libc)
set(CMAKE_C_IMPLICIT_LINK_DIRECTORIES ${CMAKE_SYSROOT}/usr/lib)
set(CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES ${CMAKE_SYSROOT}/usr/lib)

# Set the library search path
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)

# Set the header search path
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)

# Set the program search path
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM BOTH)

# Set our custom openssl directory
set(OPENSSL_ROOT_DIR /opt/openssl)

set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_SYSROOT})