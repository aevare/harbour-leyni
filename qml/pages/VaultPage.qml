import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "VaultPage.qml"

    property var folderList: []
    // Mirrors the header's SearchField text: the field lives inside the
    // ListView header component, whose ids are not reliably reachable from
    // outside it (e.g. from the ViewPlaceholder below).
    property string searchText: ""

    function reloadFolders() {
        folderList = App.folders()
    }

    // Refiltering the list can dismiss the keyboard on device even with
    // row-level model updates (root cause not pinned down yet — see
    // todo.md), so hold off until the user pauses typing. Clearing and
    // Enter apply immediately.
    Timer {
        id: searchDebounce
        interval: 400
        onTriggered: App.vaultModel.setSearchQuery(page.searchText)
    }

    function iconForType(cipherType) {
        switch (cipherType) {
        case 1: return "image://theme/icon-m-website"
        case 2: return "image://theme/icon-m-note"
        case 3: return "image://theme/icon-m-other"
        case 4: return "image://theme/icon-m-contact"
        default: return "image://theme/icon-m-other"
        }
    }

    // SilicaListView computes its initial contentY before the (header +
    // section) heights settle, landing slightly scrolled with the first
    // section pulled up under the header — scrolling away and back forces the
    // recompute that fixes it. Snapping to the top once layout settles does
    // the same thing up front. interval 0 fires on the next event-loop pass,
    // after the first layout.
    Timer {
        id: topSnap
        interval: 0
        onTriggered: listView.positionViewAtBeginning()
    }

    Component.onCompleted: {
        reloadFolders()
        topSnap.start()
    }

    Connections {
        target: App
        onVaultChanged: reloadFolders()
    }

    Connections {
        target: App.vaultModel
        // Sections appearing/disappearing re-triggers the same layout race.
        onHasFavoritesChanged: topSnap.restart()
    }

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: App.vaultModel

        // The model sorts favourites first; headers only make sense when
        // both groups exist, so they collapse when nothing is a favourite.
        section.property: "favorite"
        section.delegate: Item {
            width: listView.width
            // Use the SectionHeader's own natural height when shown — forcing
            // a taller height drops its bottom-aligned label onto the first
            // item. Collapse to 0 (single "Other items" group) otherwise.
            height: listView.model.hasFavorites ? sectionLabel.height : 0
            clip: true

            SectionHeader {
                id: sectionLabel
                width: parent.width
                text: section === "true" ? qsTr("Favourites")
                                         : qsTr("Other items")
            }
        }

        header: Column {
            width: listView.width

            PageHeader { title: qsTr("Vault") }

            SearchField {
                id: searchField
                width: parent.width
                placeholderText: qsTr("Search vault")
                inputMethodHints: Qt.ImhNoPredictiveText
                // Keep the keyboard up when focus would drift while the
                // list refilters underneath (the model emits row-level
                // updates, never a reset, for the same reason).
                focusOutBehavior: FocusBehavior.KeepFocus
                onTextChanged: {
                    page.searchText = text
                    if (text.length === 0) {
                        searchDebounce.stop()
                        App.vaultModel.setSearchQuery("")
                    } else {
                        searchDebounce.restart()
                    }
                }
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: {
                    searchDebounce.stop()
                    App.vaultModel.setSearchQuery(text)
                }
            }

            ComboBox {
                id: folderCombo
                width: parent.width
                label: qsTr("Folder")
                currentIndex: 0
                menu: ContextMenu {
                    MenuItem { text: qsTr("All items") }
                    MenuItem { text: qsTr("No folder") }
                    Repeater {
                        model: folderList
                        MenuItem { text: modelData.name }
                    }
                }
                onCurrentIndexChanged: {
                    if (currentIndex === 0) {
                        App.vaultModel.setFolderFilter("")
                    } else if (currentIndex === 1) {
                        App.vaultModel.setFolderFilter("none")
                    } else if (folderList.length > currentIndex - 2) {
                        App.vaultModel.setFolderFilter(folderList[currentIndex - 2].id)
                    }
                }
            }
        }

        PullDownMenu {
            MenuItem {
                text: qsTr("Settings")
                onClicked: pageStack.push(Qt.resolvedUrl("SettingsPage.qml"))
            }
            MenuItem {
                text: qsTr("Sync")
                onClicked: App.syncNow()
            }
            MenuItem {
                text: qsTr("Lock now")
                onClicked: App.lock()
            }
        }

        delegate: ListItem {
            id: delegate
            width: listView.width
            contentHeight: Theme.itemSizeMedium

            Image {
                id: typeIcon
                source: iconForType(model.cipherType)
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium
                anchors {
                    left: parent.left
                    leftMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }
            }

            Image {
                id: favoriteIcon
                visible: model.favorite
                // No icon-s-favorite-* exists in the theme; scale the
                // medium one down.
                source: "image://theme/icon-m-favorite-selected"
                sourceSize { width: Theme.iconSizeExtraSmall; height: Theme.iconSizeExtraSmall }
                width: Theme.iconSizeExtraSmall
                height: Theme.iconSizeExtraSmall
                anchors {
                    right: parent.right
                    rightMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }
            }

            Column {
                anchors {
                    left: typeIcon.right
                    leftMargin: Theme.paddingMedium
                    right: favoriteIcon.visible ? favoriteIcon.left : parent.right
                    rightMargin: Theme.paddingMedium
                    verticalCenter: parent.verticalCenter
                }

                Label {
                    width: parent.width
                    text: model.name
                    truncationMode: TruncationMode.Fade
                    color: delegate.highlighted ? Theme.highlightColor : Theme.primaryColor
                }
                Label {
                    width: parent.width
                    text: model.username
                    visible: text.length > 0
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeSmall
                    color: delegate.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                }
            }

            onClicked: {
                App.noteActivity()
                pageStack.push(Qt.resolvedUrl("ItemDetailPage.qml"), {
                    itemId: model.itemId,
                    name: model.name,
                    username: model.username,
                    uri: model.uri,
                    cipherType: model.cipherType,
                    hasTotp: model.hasTotp,
                    hasPassword: model.hasPassword,
                    hasNotes: model.hasNotes,
                    hasDetails: model.hasDetails
                })
            }
        }

        ViewPlaceholder {
            enabled: listView.count === 0
            text: page.searchText.length > 0 ? qsTr("No matches") : qsTr("No items")
        }

        VerticalScrollDecorator {}
    }
}
