import QtQuick 2.6
import Sailfish.Silica 1.0
import "../components"

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "VaultPage.qml"

    property var folderList: []
    // Mirrors the header SearchField text — its id isn't reachable from
    // outside the header component.
    property string searchText: ""

    function reloadFolders() {
        folderList = App.folders()
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

    // SilicaListView computes initial contentY before header/section heights
    // settle; snapping to the top once layout settles (interval 0) avoids it.
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
        // currentIndex: -1 — refiltering would steal focus from the
        // SearchField and close the keyboard.
        currentIndex: -1

        // Headers collapse to a single group when nothing is a favourite.
        section.property: "favorite"
        section.delegate: Item {
            width: listView.width
            // SectionHeader's natural height — a forced taller height drops
            // the label onto the first item.
            height: listView.model.hasFavorites ? sectionLabel.height : 0
            clip: true

            // No width override: SectionHeader sizes itself to parent.width - 2*x.
            SectionHeader {
                id: sectionLabel
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
                // Keep focus (and the keyboard) while refiltering — the model
                // emits row updates, never a reset.
                focusOutBehavior: FocusBehavior.KeepFocus
                onTextChanged: {
                    page.searchText = text
                    App.vaultModel.setSearchQuery(text)
                }
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
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
            MenuItem {
                text: qsTr("Generate password")
                onClicked: {
                    var gen = pageStack.push(
                        Qt.resolvedUrl("GeneratorDialog.qml"),
                        { acceptText: qsTr("Copy") })
                    gen.accepted.connect(function() {
                        App.copyToClipboard(gen.password)
                    })
                }
            }
            MenuItem {
                text: qsTr("New item")
                onClicked: pageStack.push(Qt.resolvedUrl("ItemEditPage.qml"),
                                          { mode: "create" })
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
                // No icon-s-favorite-* in the theme; scale the medium icon down.
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
                    folderId: model.folderId,
                    favorite: model.favorite,
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

    AppToast {}
}
