import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "UnlockPage.qml"

    onStatusChanged: {
        if (status === PageStatus.Deactivating) { passwordField.text = "" }
    }

    Component.onDestruction: passwordField.text = ""

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("Sync now")
                onClicked: App.syncNow()
            }
            MenuItem {
                text: qsTr("Settings")
                onClicked: pageStack.push(Qt.resolvedUrl("SettingsPage.qml"))
            }
            MenuItem {
                text: qsTr("Sign out")
                onClicked: remorseAction(qsTr("Signing out"), function() { App.signOut() })
            }
        }

        Column {
            id: column
            width: page.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("BitVault") }

            Image {
                anchors.horizontalCenter: parent.horizontalCenter
                source: "image://theme/icon-m-device-lock"
                width: Theme.iconSizeLarge * 2
                height: Theme.iconSizeLarge * 2
            }

            Label {
                anchors.horizontalCenter: parent.horizontalCenter
                text: App.email
                color: Theme.secondaryHighlightColor
            }

            PasswordField {
                id: passwordField
                width: parent.width
                label: qsTr("Master password")
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: App.unlock(text)
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Unlock")
                enabled: !App.busy && passwordField.text.length > 0
                onClicked: App.unlock(passwordField.text)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                running: App.busy
                size: BusyIndicatorSize.Medium
            }

            InfoLabel {
                text: App.lastError
                visible: App.lastError.length > 0
            }
        }

        VerticalScrollDecorator {}
    }
}
