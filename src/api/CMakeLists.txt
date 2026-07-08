# API layer: HTTP transport + protocol parsing. Depends on crypto and
# Qt5 Core/Network only — no GUI, headless-testable.
find_package(Qt5 COMPONENTS Core Network REQUIRED)

add_library(bitvault-api STATIC
    apiclient.cpp
    apijson.cpp
    serverconfig.cpp
)
target_include_directories(bitvault-api PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bitvault-api PUBLIC bitvault-crypto Qt5::Core Qt5::Network)
set_target_properties(bitvault-api PROPERTIES AUTOMOC ON)
