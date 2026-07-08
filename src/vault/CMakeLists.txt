# Vault layer. Phase 2: raw sync-blob persistence only; decrypted vault
# state and models arrive in Phase 3.
find_package(Qt5 COMPONENTS Core REQUIRED)

add_library(bitvault-vault STATIC
    syncstore.cpp
)
target_include_directories(bitvault-vault PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bitvault-vault PUBLIC bitvault-crypto Qt5::Core)
