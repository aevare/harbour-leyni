import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "SettingsPage.qml"

    // remorseAction() only exists on ListItem — a Button needs an explicit
    // RemorsePopup.
    RemorsePopup { id: signOutRemorse }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: page.width

            PageHeader { title: qsTr("Settings") }

            SectionHeader { text: qsTr("Security") }

            ComboBox {
                id: autoLockCombo
                width: parent.width
                label: qsTr("Auto-lock")
                property var values: [1, 5, 15, 60, 0]
                currentIndex: {
                    var i = values.indexOf(App.autoLockMinutes)
                    return i >= 0 ? i : 0
                }
                menu: ContextMenu {
                    MenuItem { text: qsTr("1 minute") }
                    MenuItem { text: qsTr("5 minutes") }
                    MenuItem { text: qsTr("15 minutes") }
                    MenuItem { text: qsTr("1 hour") }
                    MenuItem { text: qsTr("Never") }
                }
                onCurrentIndexChanged: App.autoLockMinutes = values[currentIndex]
            }

            ComboBox {
                id: clipboardCombo
                width: parent.width
                label: qsTr("Clear clipboard")
                property var values: [15, 30, 60, 0]
                currentIndex: {
                    var i = values.indexOf(App.clipboardClearSeconds)
                    return i >= 0 ? i : 0
                }
                menu: ContextMenu {
                    MenuItem { text: qsTr("15 seconds") }
                    MenuItem { text: qsTr("30 seconds") }
                    MenuItem { text: qsTr("60 seconds") }
                    MenuItem { text: qsTr("Never") }
                }
                onCurrentIndexChanged: App.clipboardClearSeconds = values[currentIndex]
            }

            TextSwitch {
                text: qsTr("Lock when minimized")
                checked: App.lockOnMinimize
                onCheckedChanged: App.lockOnMinimize = checked
            }

            SectionHeader { text: qsTr("Account") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: App.email
                color: Theme.primaryColor
                truncationMode: TruncationMode.Fade
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: App.serverUrl
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeSmall
                truncationMode: TruncationMode.Fade
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Sign out")
                onClicked: signOutRemorse.execute(qsTr("Signing out"),
                                                  function() { App.signOut() })
            }
        }

        VerticalScrollDecorator {}
    }
}
