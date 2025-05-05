# CMakeLists.txt

# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project definition
project(SecureMCP VERSION 1.0 LANGUAGES C CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Directory Variables ---
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external)
set(KEYS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/keys)

# Library source paths
set(TREZOR_CRYPTO_SRC_DIR ${EXTERNAL_DIR}/trezor-firmware/crypto)
set(NANOPB_SRC_DIR ${EXTERNAL_DIR}/nanopb)

# --- Build Output Directories ---
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# --- Find Required Packages ---
find_package(Boost 1.74 REQUIRED COMPONENTS system)
find_package(PythonInterp REQUIRED)
find_package(Threads REQUIRED)

# --- Nanopb Generation ---
set(NANOPB_GENERATED_C ${PROTO_DIR}/auth.pb.c)
set(NANOPB_GENERATED_H ${PROTO_DIR}/auth.pb.h)
set(NANOPB_PROTO_FILE ${PROTO_DIR}/auth.proto)
set(NANOPB_GENERATOR ${NANOPB_SRC_DIR}/generator/nanopb_generator.py)

add_custom_command(
    OUTPUT ${NANOPB_GENERATED_C} ${NANOPB_GENERATED_H}
    COMMAND ${PYTHON_EXECUTABLE} ${NANOPB_GENERATOR} "${NANOPB_PROTO_FILE}"
    DEPENDS ${NANOPB_PROTO_FILE} ${NANOPB_GENERATOR}
    COMMENT "Generating Nanopb sources from ${NANOPB_PROTO_FILE}"
    VERBATIM
)
add_custom_target(
    nanopb_generate ALL
    DEPENDS ${NANOPB_GENERATED_C} ${NANOPB_GENERATED_H}
)
set(NANOPB_GENERATED_SOURCES ${NANOPB_GENERATED_C})

# --- Source File Definitions ---

# Nanopb core C sources
set(NANOPB_CORE_SOURCES
    ${NANOPB_SRC_DIR}/pb_common.c
    ${NANOPB_SRC_DIR}/pb_decode.c
    ${NANOPB_SRC_DIR}/pb_encode.c
)

# Trezor C sources
set(TREZOR_CRYPTO_SOURCES
    ${TREZOR_CRYPTO_SRC_DIR}/sha2.c
    ${TREZOR_CRYPTO_SRC_DIR}/ecdsa.c
    ${TREZOR_CRYPTO_SRC_DIR}/rand.c
    ${TREZOR_CRYPTO_SRC_DIR}/secp256k1.c
    ${TREZOR_CRYPTO_SRC_DIR}/curves.c
    ${TREZOR_CRYPTO_SRC_DIR}/bignum.c
    ${TREZOR_CRYPTO_SRC_DIR}/hmac.c
    ${TREZOR_CRYPTO_SRC_DIR}/rfc6979.c
    ${TREZOR_CRYPTO_SRC_DIR}/memzero.c
    ${TREZOR_CRYPTO_SRC_DIR}/hasher.c
    ${TREZOR_CRYPTO_SRC_DIR}/address.c
    ${TREZOR_CRYPTO_SRC_DIR}/base58.c
    ${TREZOR_CRYPTO_SRC_DIR}/hmac_drbg.c
    ${TREZOR_CRYPTO_SRC_DIR}/ripemd160.c
    ${TREZOR_CRYPTO_SRC_DIR}/blake256.c
    ${TREZOR_CRYPTO_SRC_DIR}/sha3.c
    ${TREZOR_CRYPTO_SRC_DIR}/groestl.c
    ${TREZOR_CRYPTO_SRC_DIR}/blake2b.c
)

# Application C++ utility sources
set(APP_UTILS_SOURCES
    ${SRC_DIR}/network_utils.cpp
    ${SRC_DIR}/nanopb_utils.cpp
)

# Combine ALL source files needed for linking (excluding main files)
set(ALL_NON_MAIN_SOURCES
    ${APP_UTILS_SOURCES}
    ${NANOPB_CORE_SOURCES}
    ${NANOPB_GENERATED_SOURCES}
    ${TREZOR_CRYPTO_SOURCES}
)

# --- Executable Definitions ---

# Add compile definition for Trezor insecure PRNG globally or per target
add_compile_definitions(USE_INSECURE_PRNG)

# 1. Server Executable
add_executable(server
    ${SRC_DIR}/server.cpp
    ${ALL_NON_MAIN_SOURCES} # Add all other sources directly
)
# Add ALL necessary include paths for compiling ALL sources in this target
target_include_directories(server PRIVATE
    ${INCLUDE_DIR}              # For project headers
    ${PROTO_DIR}                # For auth.pb.h included by C++/C files
    ${TREZOR_CRYPTO_SRC_DIR}    # For Trezor headers
    ${NANOPB_SRC_DIR}           # For Nanopb core headers (pb.h)
    ${Boost_INCLUDE_DIRS}       # For Boost headers
    ${CMAKE_CURRENT_SOURCE_DIR} # For resolving "proto/auth.pb.h" from auth.pb.c
)
# Link server against Boost, Threads, Math libs
target_link_libraries(server PRIVATE Boost::system Threads::Threads m)
# Ensure Nanopb generation dependency is met before compiling sources that include it
add_dependencies(server nanopb_generate)

# 2. Client Executable
add_executable(client
    ${SRC_DIR}/client.cpp
    ${ALL_NON_MAIN_SOURCES} # Add all other sources directly
)
# Add ALL necessary include paths for compiling ALL sources in this target
target_include_directories(client PRIVATE
    ${INCLUDE_DIR}              # For project headers
    ${PROTO_DIR}                # For auth.pb.h included by C++/C files
    ${TREZOR_CRYPTO_SRC_DIR}    # For Trezor headers
    ${NANOPB_SRC_DIR}           # For Nanopb core headers (pb.h)
    ${Boost_INCLUDE_DIRS}       # For Boost headers
    ${CMAKE_CURRENT_SOURCE_DIR} # For resolving "proto/auth.pb.h" from auth.pb.c
)
# Link client against Boost, Threads, Math libs
target_link_libraries(client PRIVATE Boost::system Threads::Threads m)
# Ensure Nanopb generation dependency is met
add_dependencies(client nanopb_generate)


# --- Global Compile Options (Apply to all C/C++ targets) ---
add_compile_options(-Wall -Wno-deprecated-declarations -g)

# --- Final Messages ---
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Generator: ${CMAKE_GENERATOR}")
message(STATUS "Boost Include Dirs: ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost Library Dirs: ${Boost_LIBRARY_DIRS}")
message(STATUS "Executables will be placed in: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")