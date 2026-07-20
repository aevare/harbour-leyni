# The auditable crypto core. Allowed dependencies: libcrypto (OpenSSL) and
# the vendored argon2 reference implementation. NO Qt, no network, no I/O.
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(argon2 STATIC
    ${CMAKE_SOURCE_DIR}/third_party/argon2/argon2.c
    ${CMAKE_SOURCE_DIR}/third_party/argon2/core.c
    ${CMAKE_SOURCE_DIR}/third_party/argon2/encoding.c
    ${CMAKE_SOURCE_DIR}/third_party/argon2/ref.c
    ${CMAKE_SOURCE_DIR}/third_party/argon2/thread.c
    ${CMAKE_SOURCE_DIR}/third_party/argon2/blake2/blake2b.c
)
target_include_directories(argon2 PUBLIC ${CMAKE_SOURCE_DIR}/third_party/argon2)
target_link_libraries(argon2 PUBLIC Threads::Threads)

add_library(leyni-crypto STATIC
    base64.cpp
    crypto.cpp
    encstring.cpp
    kdf.cpp
    keys.cpp
    passwordgen.cpp
    pinwrap.cpp
    securebytes.cpp
    totp.cpp
)
target_include_directories(leyni-crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(leyni-crypto PUBLIC OpenSSL::Crypto argon2)
