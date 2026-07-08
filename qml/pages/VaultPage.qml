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

    function iconForType(cipherType) {
        switch (cipherType) {
        case 1: return "image://theme/icon-m-website"
        case 2: return "image://theme/icon-m-note"
        case 3: return "image://theme/icon-m-other"
        case 4: return "image://theme/icon-m-contact"
        default: return "image://theme/icon-m-other"
        }
    }

    Component.onCompleted: reloadFolders()

    Connections {
        target: App
        onVaultChanged: reloadFolders()
    }

    SilicaListView {
        id: listView
        anchors.fill: parent
        model: App.vaultModel

        header: Column {
            width: listView.width

            PageHeader { title: qsTr("Vault") }

            SearchField {
                id: searchField
                width: parent.width
                placeholderText: qsTr("Search vault")
                inputMethodHints: Qt.ImhNoPredictiveText
                onTextChanged: {
                    page.searchText = text
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
                    hasPassword: model.hasPassword
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
