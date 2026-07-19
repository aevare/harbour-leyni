add_executable(crypto_tests
    crypto/base64_tests.cpp
    crypto/encstring_tests.cpp
    crypto/kdf_bounds_tests.cpp
    crypto/main.cpp
    crypto/pinwrap_tests.cpp
    crypto/rsa_tests.cpp
    crypto/securebytes_tests.cpp
    crypto/totp_tests.cpp
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

    # One-off fixture generator (Phase 3): populates a local Vaultwarden and
    # saves its /api/sync response to tests/fixtures/sync.json. Not a test —
    # no add_test — run manually against a live server; see
    # tests/fixtures/README.md.
    add_executable(generate_sync_fixture fixtures/generate_sync_fixture.cpp)
    target_link_libraries(generate_sync_fixture PRIVATE
        bitvault-api bitvault-crypto Qt5::Core Qt5::Network OpenSSL::Crypto)

    # Vault layer tests (Phase 3): offline, unlock the committed sync.json
    # fixture with no network. Part of the default `ctest -LE integration`
    # run; see doc/TESTING.md Layer 2.
    add_executable(vault_tests vault/vault_tests.cpp)
    target_compile_definitions(vault_tests PRIVATE
        BITVAULT_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
    target_link_libraries(vault_tests PRIVATE
        bitvault-vault bitvault-api bitvault-crypto Qt5::Core Qt5::Network)
    add_test(NAME vault_tests COMMAND vault_tests)
endif()
