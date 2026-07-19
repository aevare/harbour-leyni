import QtQuick 2.6
import Sailfish.Silica 1.0

// Collects the master password (to authorize the change and re-derive the
// master key) and a new PIN. On accept, the caller reads `masterPassword` and
// `pin` and hands them to App.enablePin(). Nothing is stored here.
Dialog {
    id: dialog
    allowedOrientations: Orientation.All

    readonly property int minPinLength: 4
    property alias masterPassword: passwordField.text
    property alias pin: pinField.text

    canAccept: passwordField.text.length > 0
               && pinField.text.length >= minPinLength
               && pinField.text === confirmField.text

    // Clear the entered secrets from QML once the dialog goes away.
    function clearFields() {
        passwordField.text = ""
        pinField.text = ""
        confirmField.text = ""
    }
    Component.onDestruction: clearFields()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader { title: qsTr("Enable PIN unlock") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: Theme.secondaryHighlightColor
                font.pixelSize: Theme.fontSizeSmall
                text: qsTr("A PIN is quicker but much weaker than your master "
                           + "password. Anyone who copies the app's data off "
                           + "the phone can try every PIN offline. After %1 "
                           + "wrong PINs the app clears it and asks for your "
                           + "master password.").arg(3)
            }

            PasswordField {
                id: passwordField
                width: parent.width
                label: qsTr("Master password")
                placeholderText: qsTr("Master password")
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: pinField.focus = true
            }

            PasswordField {
                id: pinField
                width: parent.width
                label: qsTr("New PIN (at least %1 digits)").arg(minPinLength)
                placeholderText: qsTr("New PIN")
                inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: confirmField.focus = true
            }

            PasswordField {
                id: confirmField
                width: parent.width
                label: qsTr("Confirm PIN")
                placeholderText: qsTr("Confirm PIN")
                inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText | Qt.ImhSensitiveData
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: if (dialog.canAccept) dialog.accept()
            }
        }
    }
}
