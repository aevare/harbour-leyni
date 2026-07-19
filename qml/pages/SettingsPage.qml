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

            // Both combos: currentIndex is set ONCE at completion instead of
            // being bound — a binding here depends on the very setting the
            // change handler writes, which is a binding loop. The `ready`
            // guard keeps initialization from echoing a write back.
            ComboBox {
                id: autoLockCombo
                width: parent.width
                label: qsTr("Auto-lock")
                property var values: [1, 5, 15, 60, 0]
                property bool ready: false
                Component.onCompleted: {
                    var i = values.indexOf(App.autoLockMinutes)
                    currentIndex = i >= 0 ? i : 0
                    ready = true
                }
                menu: ContextMenu {
                    MenuItem { text: qsTr("1 minute") }
                    MenuItem { text: qsTr("5 minutes") }
                    MenuItem { text: qsTr("15 minutes") }
                    MenuItem { text: qsTr("1 hour") }
                    MenuItem { text: qsTr("Never") }
                }
                onCurrentIndexChanged: {
                    if (ready) { App.autoLockMinutes = values[currentIndex] }
                }
            }

            ComboBox {
                id: clipboardCombo
                width: parent.width
                label: qsTr("Clear clipboard")
                property var values: [15, 30, 60, 0]
                property bool ready: false
                Component.onCompleted: {
                    var i = values.indexOf(App.clipboardClearSeconds)
                    currentIndex = i >= 0 ? i : 0
                    ready = true
                }
                menu: ContextMenu {
                    MenuItem { text: qsTr("15 seconds") }
                    MenuItem { text: qsTr("30 seconds") }
                    MenuItem { text: qsTr("60 seconds") }
                    MenuItem { text: qsTr("Never") }
                }
                onCurrentIndexChanged: {
                    if (ready) { App.clipboardClearSeconds = values[currentIndex] }
                }
            }

            TextSwitch {
                text: qsTr("Lock when minimized")
                // automaticCheck off + write-on-click avoids the binding
                // loop of checked ↔ the setting it writes.
                automaticCheck: false
                checked: App.lockOnMinimize
                onClicked: App.lockOnMinimize = !App.lockOnMinimize
            }

            TextSwitch {
                text: qsTr("PIN unlock")
                description: qsTr("Unlock with a short PIN instead of your "
                                  + "master password. Weaker: a copy of the "
                                  + "app's data can be brute-forced offline.")
                automaticCheck: false
                checked: App.pinEnabled
                enabled: !App.busy
                onClicked: {
                    if (App.pinEnabled) {
                        App.disablePin()
                    } else {
                        var dialog = pageStack.push(
                            Qt.resolvedUrl("EnablePinDialog.qml"))
                        dialog.accepted.connect(function() {
                            App.enablePin(dialog.masterPassword, dialog.pin)
                        })
                    }
                }
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
