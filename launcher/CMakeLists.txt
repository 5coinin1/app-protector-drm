cmake_minimum_required(VERSION 3.15)
project(launcher C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Dung chung module C voi protector (mot nguon code duy nhat).
set(PROTECTOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../protector")

# --- libsodium + OpenSSL (MSYS2) ---
get_filename_component(_cc_dir "${CMAKE_C_COMPILER}" DIRECTORY)
get_filename_component(MINGW_ROOT "${_cc_dir}" DIRECTORY)
find_path(SODIUM_INCLUDE_DIR sodium.h HINTS "${MINGW_ROOT}/include")
find_library(SODIUM_STATIC_LIB NAMES libsodium.a sodium HINTS "${MINGW_ROOT}/lib")
find_library(CRYPTO_LIB NAMES libcrypto.a crypto HINTS "${MINGW_ROOT}/lib")
if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_STATIC_LIB OR NOT CRYPTO_LIB)
  message(FATAL_ERROR "Thieu libsodium/openssl. Cai: pacman -S mingw-w64-x86_64-libsodium mingw-w64-x86_64-openssl")
endif()

add_executable(launcher
  src/main.c
  src/runner.c
  src/fingerprint.c
  src/entitlement.c
  # module dung chung tu protector (KHONG gom main.c cua protector)
  ${PROTECTOR_DIR}/src/crypto.c
  ${PROTECTOR_DIR}/src/archive.c
  ${PROTECTOR_DIR}/src/manifest.c
  ${PROTECTOR_DIR}/src/util.c
  ${PROTECTOR_DIR}/vendor/cjson/cJSON.c
  ${PROTECTOR_DIR}/vendor/miniz/miniz.c
)

target_include_directories(launcher PRIVATE
  include
  ${PROTECTOR_DIR}/include
  ${PROTECTOR_DIR}/vendor/cjson
  ${PROTECTOR_DIR}/vendor/miniz
  ${SODIUM_INCLUDE_DIR}
)

target_compile_definitions(launcher PRIVATE SODIUM_STATIC=1)
target_link_libraries(launcher PRIVATE ${SODIUM_STATIC_LIB} ${CRYPTO_LIB})
if(WIN32)
  target_link_libraries(launcher PRIVATE advapi32 ws2_32 crypt32 bcrypt user32)
endif()
