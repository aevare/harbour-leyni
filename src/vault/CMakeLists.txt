# Vault layer: sync-blob persistence, sync parsing, and the in-memory
# decrypted vault with its lock/unlock lifecycle.
find_package(Qt5 COMPONENTS Core REQUIRED)

add_library(leyni-vault STATIC
    pinstore.cpp
    syncparser.cpp
    syncstore.cpp
    vault.cpp
    vaultmodel.cpp
)
set_target_properties(leyni-vault PROPERTIES AUTOMOC ON)
target_include_directories(leyni-vault PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(leyni-vault PUBLIC leyni-crypto Qt5::Core)
