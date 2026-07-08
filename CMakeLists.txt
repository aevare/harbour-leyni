cmake_minimum_required(VERSION 3.10)
project(harbour-bitvault C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_APP "Build the Sailfish OS application (requires the SFOS SDK)" ON)
option(BUILD_API "Build the API/vault layers and their tests (requires Qt5 Core+Network)" OFF)

enable_testing()
add_subdirectory(src/crypto)
if(BUILD_APP OR BUILD_API)
    add_subdirectory(src/api)
    add_subdirectory(src/vault)
endif()
add_subdirectory(tests)

if(BUILD_APP)
    find_package(Qt5 COMPONENTS Core Network Qml Gui Quick REQUIRED)

    include(FindPkgConfig)
    pkg_search_module(SAILFISH sailfishapp REQUIRED)

    set(CMAKE_AUTOMOC ON)
    set(CMAKE_INCLUDE_CURRENT_DIR ON)

    # Destination dirs created by install() otherwise get umask-derived 775,
    # which rpmlint rejects as non-standard-dir-perm.
    set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

    add_executable(harbour-bitvault src/main.cpp)
    target_compile_definitions(harbour-bitvault PRIVATE
        $<$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>:QT_QML_DEBUG>
    )
    # No $<BUILD_INTERFACE:> genex here: on the SFOS 5.0 target's CMake it
    # mangles the first pkg-config dir into a build-dir-relative path.
    target_include_directories(harbour-bitvault PRIVATE ${SAILFISH_INCLUDE_DIRS})
    target_link_libraries(harbour-bitvault
        Qt5::Quick
        bitvault-api
        bitvault-vault
        ${SAILFISH_LDFLAGS}
    )

    install(TARGETS harbour-bitvault RUNTIME DESTINATION bin)
    # Explicit 755/644: install(DIRECTORY) otherwise inherits host-side dir
    # permissions (775 here), which rpmlint rejects as non-standard-dir-perm.
    set(INSTALL_PERMS
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                              GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(DIRECTORY qml DESTINATION share/harbour-bitvault ${INSTALL_PERMS})
    install(DIRECTORY translations DESTINATION share/harbour-bitvault ${INSTALL_PERMS}
            FILES_MATCHING PATTERN "*.qm")
    install(FILES harbour-bitvault.desktop DESTINATION share/applications)
    install(FILES icons/86x86/harbour-bitvault.png   DESTINATION share/icons/hicolor/86x86/apps)
    install(FILES icons/108x108/harbour-bitvault.png DESTINATION share/icons/hicolor/108x108/apps)
    install(FILES icons/128x128/harbour-bitvault.png DESTINATION share/icons/hicolor/128x128/apps)
    install(FILES icons/172x172/harbour-bitvault.png DESTINATION share/icons/hicolor/172x172/apps)

    FILE(GLOB TsFiles "translations/*.ts")
    add_custom_target(distfiles
        SOURCES
            harbour-bitvault.desktop
            qml/harbour-bitvault.qml
            qml/cover/CoverPage.qml
            qml/pages/FirstPage.qml
            rpm/harbour-bitvault.changes
            rpm/harbour-bitvault.spec
            ${TsFiles})
endif()
