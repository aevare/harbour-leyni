add_executable(crypto_tests
    crypto/base64_tests.cpp
    crypto/encstring_tests.cpp
    crypto/kdf_bounds_tests.cpp
    crypto/main.cpp
    crypto/rsa_tests.cpp
    crypto/securebytes_tests.cpp
    crypto/vector_tests.cpp
)
target_link_libraries(crypto_tests PRIVATE bitvault-crypto)
add_test(NAME crypto_tests COMMAND crypto_tests)
