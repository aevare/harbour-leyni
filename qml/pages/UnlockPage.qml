import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "UnlockPage.qml"

    // Start in PIN mode when a PIN is set up; the "Use master password" link
    // switches to the password field. When no PIN exists, only the password
    // field is shown. This is presentation only — the C++ side decides which
    // unlock actually succeeds.
    property bool usePassword: !App.pinEnabled

    function clearFields() {
        passwordField.text = ""
        pinField.text = ""
    }

    onStatusChanged: {
        if (status === PageStatus.Deactivating) { clearFields() }
    }

    Component.onDestruction: clearFields()

    // remorseAction() only exists on ListItem — a pulley MenuItem needs an
    // explicit RemorsePopup.
    RemorsePopup { id: signOutRemorse }

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
                onClicked: signOutRemorse.execute(qsTr("Signing out"),
                                                  function() { App.signOut() })
            }
        }

        Column {
            id: column
            width: page.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Leyni") }

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

            // --- PIN entry (default when a PIN is set up) ---
            PasswordField {
                id: pinField
                visible: !page.usePassword
                width: parent.width
                label: qsTr("PIN")
                inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: App.unlockWithPin(text)
            }

            Button {
                visible: !page.usePassword
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Unlock")
                enabled: !App.busy && pinField.text.length > 0
                onClicked: App.unlockWithPin(pinField.text)
            }

            // --- master password entry ---
            PasswordField {
                id: passwordField
                visible: page.usePassword
                width: parent.width
                label: qsTr("Master password")
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: App.unlock(text)
            }

            Button {
                visible: page.usePassword
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Unlock")
                enabled: !App.busy && passwordField.text.length > 0
                onClicked: App.unlock(passwordField.text)
            }

            // Toggle between the two. Hidden when no PIN exists (nothing to
            // toggle to).
            BackgroundItem {
                visible: App.pinEnabled
                width: parent.width
                height: toggleLabel.implicitHeight + Theme.paddingMedium * 2
                onClicked: {
                    page.clearFields()
                    page.usePassword = !page.usePassword
                }
                Label {
                    id: toggleLabel
                    anchors.centerIn: parent
                    text: page.usePassword ? qsTr("Use PIN")
                                           : qsTr("Use master password")
                    color: Theme.highlightColor
                    font.pixelSize: Theme.fontSizeSmall
                }
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
