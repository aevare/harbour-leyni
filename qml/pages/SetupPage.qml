import QtQuick 2.6
import Sailfish.Silica 1.0
import "../components"

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "SetupPage.qml"

    // The router keeps SetupPage in the "login" family, so navigate explicitly.
    function saveAndContinue() {
        App.configureAccount(serverField.text, emailField.text)
        pageStack.replaceAbove(null, Qt.resolvedUrl("LoginPage.qml"))
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: page.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Leyni") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: qsTr("Leyni — unofficial Bitwarden client")
                color: Theme.secondaryHighlightColor
                wrapMode: Text.WordWrap
            }

            TextField {
                id: serverField
                width: parent.width
                label: qsTr("Server URL")
                placeholderText: qsTr("https://vault.example.com")
                description: qsTr("Using the official bitwarden.com cloud? Enter https://vault.bitwarden.com")
                inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: emailField.focus = true
            }

            TextField {
                id: emailField
                width: parent.width
                label: qsTr("Email")
                placeholderText: qsTr("you@example.com")
                inputMethodHints: Qt.ImhEmailCharactersOnly | Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.enabled: serverField.text.length > 0 && emailField.text.length > 0
                EnterKey.onClicked: saveAndContinue()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Continue")
                enabled: serverField.text.length > 0 && emailField.text.length > 0
                onClicked: saveAndContinue()
            }
        }

        VerticalScrollDecorator {}
    }

    AppToast {}
}
