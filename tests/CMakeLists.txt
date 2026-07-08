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

# API layer tests (Phase 2). Only built when src/api was configured in
# (BUILD_APP or BUILD_API); see doc/TESTING.md Layer 3.
if(TARGET bitvault-api)
    find_package(Qt5 COMPONENTS Core Network REQUIRED)
    find_package(OpenSSL REQUIRED)

    # Offline, no-network unit tests: pure request/response parsing and
    # SyncStore file I/O. Part of the default `ctest -LE integration` run.
    add_executable(api_unit_tests api/api_unit_tests.cpp)
    target_link_libraries(api_unit_tests PRIVATE
        bitvault-api bitvault-vault bitvault-crypto Qt5::Core Qt5::Network)
    add_test(NAME api_unit_tests COMMAND api_unit_tests)

    # Live end-to-end tests against a real server (default
    # http://127.0.0.1:8000, override with BITVAULT_TEST_SERVER). Opt-in via
    # `ctest -L integration`; never runs in the plain unit-test job.
    add_executable(api_integration_tests api/api_integration_tests.cpp)
    target_link_libraries(api_integration_tests PRIVATE
        bitvault-api bitvault-vault bitvault-crypto Qt5::Core Qt5::Network
        OpenSSL::Crypto)
    add_test(NAME api_integration_tests COMMAND api_integration_tests)
    set_tests_properties(api_integration_tests PROPERTIES LABELS "integration")
endif()
