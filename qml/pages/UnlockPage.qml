import QtQuick 2.6
import Sailfish.Silica 1.0
import "../components"

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "UnlockPage.qml"

    // Presentation only — C++ decides which unlock succeeds.
    property bool usePassword: !App.pinEnabled

    function clearFields() {
        passwordField.text = ""
        pinField.text = ""
    }

    function focusInput() {
        if (page.usePassword) {
            passwordField.forceActiveFocus()
        } else {
            pinField.forceActiveFocus()
        }
    }

    onStatusChanged: {
        if (status === PageStatus.Active) { focusInput() }
        else if (status === PageStatus.Deactivating) { clearFields() }
    }

    Component.onDestruction: clearFields()

    // remorseAction() exists only on ListItem; a pulley MenuItem needs a RemorsePopup.
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

            BackgroundItem {
                visible: App.pinEnabled
                width: parent.width
                height: toggleLabel.implicitHeight + Theme.paddingMedium * 2
                onClicked: {
                    page.clearFields()
                    page.usePassword = !page.usePassword
                    page.focusInput()
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

            InlineBanner {
                shown: App.lastError.length > 0
                variant: "error"
                title: qsTr("Couldn't unlock")
                text: App.lastError
            }
        }

        VerticalScrollDecorator {}
    }

    AppToast {}
}
