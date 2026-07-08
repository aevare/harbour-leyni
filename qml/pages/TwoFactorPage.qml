import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "TwoFactorPage.qml"

    // Default to the authenticator app (0) whenever it is offered.
    property int selectedProvider: App.twoFactorProviders.indexOf(0) !== -1
                                    ? 0
                                    : (App.twoFactorProviders.length > 0 ? App.twoFactorProviders[0] : 0)

    onStatusChanged: {
        if (status === PageStatus.Deactivating) { codeField.text = "" }
    }

    Component.onDestruction: codeField.text = ""

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("Cancel")
                onClicked: App.cancelLogin()
            }
        }

        Column {
            id: column
            width: page.width
            spacing: Theme.paddingLarge

            PageHeader { title: qsTr("Verify it's you") }

            ComboBox {
                id: providerCombo
                width: parent.width
                label: qsTr("Verification method")
                visible: App.twoFactorProviders.length > 1
                currentIndex: App.twoFactorProviders.indexOf(0) !== -1
                              ? App.twoFactorProviders.indexOf(0) : 0
                menu: ContextMenu {
                    Repeater {
                        model: App.twoFactorProviders
                        MenuItem {
                            text: modelData === 0 ? qsTr("Authenticator app") : qsTr("Email")
                        }
                    }
                }
                onCurrentIndexChanged: {
                    if (App.twoFactorProviders.length > currentIndex) {
                        selectedProvider = App.twoFactorProviders[currentIndex]
                    }
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Send code")
                visible: selectedProvider === 1
                enabled: !App.busy
                onClicked: App.requestEmailCode()
            }

            TextField {
                id: codeField
                width: parent.width
                label: qsTr("Verification code")
                placeholderText: qsTr("123456")
                inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                EnterKey.onClicked: App.submitTwoFactor(selectedProvider, text, rememberSwitch.checked)
            }

            TextSwitch {
                id: rememberSwitch
                text: qsTr("Remember this device")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Verify")
                enabled: !App.busy && codeField.text.length > 0
                onClicked: App.submitTwoFactor(selectedProvider, codeField.text, rememberSwitch.checked)
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
