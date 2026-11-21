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
    # .ts catalogs are committed; the build only compiles the language-specific
    # ones to .qm (lrelease ships in qt5-qttools-linguist, a spec BuildRequires)
    # so rpm builds stay reproducible — no lupdate run at build time. The base
    # catalog (harbour-leyni.ts) holds the English source strings and needs no
    # .qm: untranslated qsTr() falls back to the source text.
    FILE(GLOB TsFiles "translations/*.ts")
    find_program(LRELEASE_EXECUTABLE NAMES lrelease lrelease-qt5)
    if(NOT LRELEASE_EXECUTABLE)
        message(FATAL_ERROR "lrelease not found (install qt5-qttools-linguist)")
    endif()
    set(QM_FILES)
    foreach(TsFile ${TsFiles})
        get_filename_component(QM_NAME ${TsFile} NAME_WE)
        if(QM_NAME STREQUAL "harbour-leyni")
            continue()
        endif()
        set(QM_FILE ${CMAKE_CURRENT_BINARY_DIR}/${QM_NAME}.qm)
        # TsFile is already an absolute path (FILE(GLOB) without RELATIVE).
        add_custom_command(OUTPUT ${QM_FILE}
            COMMAND ${LRELEASE_EXECUTABLE} ${TsFile} -qm ${QM_FILE}
            DEPENDS ${TsFile}
            COMMENT "lrelease ${TsFile}")
        list(APPEND QM_FILES ${QM_FILE})
    endforeach()
    add_custom_target(translations ALL DEPENDS ${QM_FILES})
    install(FILES ${QM_FILES} DESTINATION share/harbour-leyni/translations)
    install(FILES harbour-leyni.desktop DESTINATION share/applications)
    install(FILES icons/86x86/harbour-leyni.png   DESTINATION share/icons/hicolor/86x86/apps)
    install(FILES icons/108x108/harbour-leyni.png DESTINATION share/icons/hicolor/108x108/apps)
    install(FILES icons/128x128/harbour-leyni.png DESTINATION share/icons/hicolor/128x128/apps)
    install(FILES icons/172x172/harbour-leyni.png DESTINATION share/icons/hicolor/172x172/apps)

    FILE(GLOB_RECURSE QmlFiles "qml/*.qml")
    add_custom_target(distfiles
        SOURCES
            harbour-leyni.desktop
            rpm/harbour-leyni.changes
            rpm/harbour-leyni.spec
            ${QmlFiles}
            ${TsFiles})
endif()
