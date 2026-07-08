add_library(bitvault-crypto STATIC
    crypto.cpp
)

target_include_directories(bitvault-crypto PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

set_target_properties(bitvault-crypto PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)
