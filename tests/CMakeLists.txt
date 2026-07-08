add_executable(crypto_tests crypto_tests.cpp)

target_link_libraries(crypto_tests
    bitvault-crypto
)

set_target_properties(crypto_tests PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

add_test(NAME crypto_tests COMMAND crypto_tests)
