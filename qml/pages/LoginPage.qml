import QtQuick 2.6
import Sailfish.Silica 1.0
import "../components"

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "LoginPage.qml"

    // Never let the typed password linger once this page is hidden.
    onStatusChanged: {
        if (status === PageStatus.Deactivating) { passwordField.text = "" }
    }

    Component.onDestruction: passwordField.text = ""

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("Change account")
                onClicked: pageStack.push(Qt.resolvedUrl("SetupPage.qml"))
            }
        }

        Column {
            id: column
            width: page.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Sign in") }

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

            PasswordField {
                id: passwordField
                width: parent.width
                label: qsTr("Master password")
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: App.startLogin(text)
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Sign in")
                enabled: !App.busy && passwordField.text.length > 0
                onClicked: App.startLogin(passwordField.text)
            }

            InlineBanner {
                shown: App.lastError.length > 0
                variant: "error"
                title: qsTr("Couldn't sign in")
                text: App.lastError
            }
        }

        VerticalScrollDecorator {}
    }

    AppToast {}
}
