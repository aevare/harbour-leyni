cmake_minimum_required(VERSION 3.10)
project(harbour-leyni C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# The SFOS app links -pie (sailfishapp requirement), so every static lib
# feeding it must be position-independent.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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
    find_package(Qt5 COMPONENTS Core Concurrent Network Qml Gui Quick REQUIRED)

    include(FindPkgConfig)
    pkg_search_module(SAILFISH sailfishapp REQUIRED)
    pkg_search_module(SECRETS sailfishsecrets REQUIRED)

    set(CMAKE_AUTOMOC ON)
    set(CMAKE_INCLUDE_CURRENT_DIR ON)

    # Destination dirs created by install() otherwise get umask-derived 775,
    # which rpmlint rejects as non-standard-dir-perm.
    set(CMAKE_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
        OWNER_READ OWNER_WRITE OWNER_EXECUTE
        GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

    # Version shown in Settings (App.appVersion). rpm builds pass
    # -DLEYNI_VERSION=%{version} from the spec (the release workflow already
    # verifies tag == spec Version); a LEYNI_VERSION env var covers direct
    # local cmake runs; otherwise fall back to "dev".
    if(NOT DEFINED LEYNI_VERSION)
        if(DEFINED ENV{LEYNI_VERSION})
            set(LEYNI_VERSION "$ENV{LEYNI_VERSION}")
        else()
            set(LEYNI_VERSION "dev")
        endif()
    endif()

    add_executable(harbour-leyni
        src/main.cpp
        src/ui/appcontroller.cpp
        src/ui/secretstore.cpp
    )
    target_compile_definitions(harbour-leyni PRIVATE
        $<$<OR:$<CONFIG:Debug>,$<CONFIG:RelWithDebInfo>>:QT_QML_DEBUG>
        LEYNI_APP_VERSION="${LEYNI_VERSION}"
    )
    # No $<BUILD_INTERFACE:> genex here: on the SFOS 5.0 target's CMake it
    # mangles the first pkg-config dir into a build-dir-relative path.
    target_include_directories(harbour-leyni PRIVATE
        ${SAILFISH_INCLUDE_DIRS} ${SECRETS_INCLUDE_DIRS})
    target_link_libraries(harbour-leyni
        Qt5::Quick
        Qt5::Concurrent
        leyni-api
        leyni-vault
        ${SAILFISH_LDFLAGS}
        ${SECRETS_LDFLAGS}
    )

    install(TARGETS harbour-leyni RUNTIME DESTINATION bin)
    # Explicit 755/644: install(DIRECTORY) otherwise inherits host-side dir
    # permissions (775 here), which rpmlint rejects as non-standard-dir-perm.
    set(INSTALL_PERMS
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                              GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(DIRECTORY qml DESTINATION share/harbour-leyni ${INSTALL_PERMS})
    install(DIRECTORY translations DESTINATION share/harbour-leyni ${INSTALL_PERMS}
            FILES_MATCHING PATTERN "*.qm")
    install(FILES harbour-leyni.desktop DESTINATION share/applications)
    install(FILES icons/86x86/harbour-leyni.png   DESTINATION share/icons/hicolor/86x86/apps)
    install(FILES icons/108x108/harbour-leyni.png DESTINATION share/icons/hicolor/108x108/apps)
    install(FILES icons/128x128/harbour-leyni.png DESTINATION share/icons/hicolor/128x128/apps)
    install(FILES icons/172x172/harbour-leyni.png DESTINATION share/icons/hicolor/172x172/apps)

    FILE(GLOB TsFiles "translations/*.ts")
    FILE(GLOB_RECURSE QmlFiles "qml/*.qml")
    add_custom_target(distfiles
        SOURCES
            harbour-leyni.desktop
            rpm/harbour-leyni.changes
            rpm/harbour-leyni.spec
            ${QmlFiles}
            ${TsFiles})
endif()
