cmake_minimum_required(VERSION 3.15)
project(protector C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --- libsodium (MSYS2: C:/msys64/mingw64) ---
# Suy ra prefix mingw tu vi tri compiler (.../mingw64/bin/gcc -> .../mingw64).
get_filename_component(_cc_dir "${CMAKE_C_COMPILER}" DIRECTORY)
get_filename_component(MINGW_ROOT "${_cc_dir}" DIRECTORY)
find_path(SODIUM_INCLUDE_DIR sodium.h HINTS "${MINGW_ROOT}/include")
find_library(SODIUM_STATIC_LIB NAMES libsodium.a sodium HINTS "${MINGW_ROOT}/lib")
if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_STATIC_LIB)
  message(FATAL_ERROR "Khong tim thay libsodium. Cai: pacman -S mingw-w64-x86_64-libsodium")
endif()

# --- OpenSSL libcrypto (cho AES-256-GCM, chay moi CPU) ---
find_library(CRYPTO_LIB NAMES libcrypto.a crypto HINTS "${MINGW_ROOT}/lib")
if(NOT CRYPTO_LIB)
  message(FATAL_ERROR "Khong tim thay libcrypto. Cai: pacman -S mingw-w64-x86_64-openssl")
endif()

add_executable(protector
  src/main.c
  src/crypto.c
  src/archive.c
  src/manifest.c
  src/util.c
  vendor/cjson/cJSON.c
  vendor/miniz/miniz.c
)

target_include_directories(protector PRIVATE
  include
  vendor/cjson
  vendor/miniz
  ${SODIUM_INCLUDE_DIR}
)

# Link static libsodium -> exe chay doc lap. SODIUM_STATIC tat dllimport.
target_compile_definitions(protector PRIVATE SODIUM_STATIC=1)
target_link_libraries(protector PRIVATE ${SODIUM_STATIC_LIB} ${CRYPTO_LIB})

# Tren Windows: libsodium + OpenSSL static can cac lib he thong nay.
if(WIN32)
  target_link_libraries(protector PRIVATE advapi32 ws2_32 crypt32 bcrypt user32)
endif()
