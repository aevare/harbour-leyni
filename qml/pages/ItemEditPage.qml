import QtQuick 2.6
import Sailfish.Silica 1.0
import "../components"

// Create/edit a Login or Secure Note. Plaintext is encrypted in the vault
// layer — never stored locally. On edit, fields are prefilled so untouched
// values are re-saved unchanged.
Dialog {
    id: dialog
    allowedOrientations: Orientation.All
    readonly property string pageName: "ItemEditPage.qml"

    property string mode: "create"       // "create" | "edit"
    property string itemId: ""
    property int cipherType: 1            // 1 = Login, 2 = Secure note

    property string presetName: ""
    property string presetUsername: ""
    property string presetUri: ""
    property string presetFolderId: ""
    property bool presetFavorite: false

    property var folderList: []

    canAccept: nameField.text.trim().length > 0

    function clearSecrets() {
        passwordField.text = ""
        totpField.text = ""
        notesField.text = ""
    }
    Component.onDestruction: clearSecrets()

    function folderIndexFor(id) {
        if (!id) { return 0 }
        for (var i = 0; i < folderList.length; i++) {
            if (folderList[i].id === id) { return i + 1 }
        }
        return 0
    }

    function selectedFolderId() {
        var i = folderCombo.currentIndex
        return i <= 0 ? "" : folderList[i - 1].id
    }

    function collectFields() {
        var f = {
            "name": nameField.text.trim(),
            "notes": notesField.text,
            "folderId": selectedFolderId(),
            "favorite": favoriteSwitch.checked
        }
        if (cipherType === 1) {
            f.username = usernameField.text
            f.password = passwordField.text
            f.uri = uriField.text
            f.totp = totpField.text
        }
        return f
    }

    Component.onCompleted: {
        folderList = App.folders()
        folderCombo.currentIndex = folderIndexFor(presetFolderId)
        if (mode === "edit") {
            if (cipherType === 1) {
                passwordField.text = App.itemPassword(itemId)
                totpField.text = App.itemTotpSecret(itemId)
            }
            notesField.text = App.itemNotes(itemId)
        }
    }

    onAccepted: {
        if (mode === "edit") {
            App.saveItem(itemId, collectFields())
        } else {
            App.createItem(cipherType, collectFields())
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                title: mode === "edit" ? qsTr("Edit item") : qsTr("New item")
                acceptText: qsTr("Save")
            }

            // Type can't change on edit.
            ComboBox {
                id: typeCombo
                visible: mode === "create"
                width: parent.width
                label: qsTr("Type")
                currentIndex: 0
                menu: ContextMenu {
                    MenuItem { text: qsTr("Login") }
                    MenuItem { text: qsTr("Secure note") }
                }
                onCurrentIndexChanged: cipherType = (currentIndex === 1 ? 2 : 1)
            }

            TextField {
                id: nameField
                width: parent.width
                label: qsTr("Name")
                placeholderText: qsTr("Name")
                text: presetName
                inputMethodHints: Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: focus = false
            }

            TextField {
                id: usernameField
                visible: cipherType === 1
                width: parent.width
                label: qsTr("Username")
                placeholderText: qsTr("Username")
                text: presetUsername
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            PasswordField {
                id: passwordField
                visible: cipherType === 1
                width: parent.width
                label: qsTr("Password")
                placeholderText: qsTr("Password")
            }

            Button {
                visible: cipherType === 1
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Generate password")
                onClicked: {
                    var gen = pageStack.push(
                        Qt.resolvedUrl("GeneratorDialog.qml"),
                        { acceptText: qsTr("Use") })
                    gen.accepted.connect(function() {
                        passwordField.text = gen.password
                    })
                }
            }

            TextField {
                id: uriField
                visible: cipherType === 1
                width: parent.width
                label: qsTr("Website (URI)")
                placeholderText: qsTr("https://example.com")
                text: presetUri
                inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            TextField {
                id: totpField
                visible: cipherType === 1
                width: parent.width
                label: qsTr("Authenticator key (TOTP)")
                placeholderText: qsTr("otpauth:// URI or secret")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
            }

            TextArea {
                id: notesField
                width: parent.width
                label: qsTr("Notes")
                placeholderText: qsTr("Notes")
            }

            ComboBox {
                id: folderCombo
                width: parent.width
                label: qsTr("Folder")
                currentIndex: 0
                menu: ContextMenu {
                    MenuItem { text: qsTr("No folder") }
                    Repeater {
                        model: folderList
                        MenuItem { text: modelData.name }
                    }
                }
            }

            TextSwitch {
                id: favoriteSwitch
                text: qsTr("Favourite")
                checked: presetFavorite
                automaticCheck: true
            }
        }

        VerticalScrollDecorator {}
    }

    AppToast {}
}
