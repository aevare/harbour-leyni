import QtQuick 2.6
import Sailfish.Silica 1.0

Page {
    id: page
    allowedOrientations: Orientation.All
    readonly property string pageName: "ItemDetailPage.qml"

    // Set by VaultPage when pushing this page. Display data only — never
    // the secret payloads themselves.
    property string itemId: ""
    property string name: ""
    property string username: ""
    property string uri: ""
    property int cipherType: 1
    property bool hasTotp: false
    property bool hasPassword: false

    // Secrets fetched on demand. Every one of these MUST be cleared when
    // the page stops being usable (destroyed, hidden, or the vault locks)
    // — see clearSecrets() below.
    property string revealedPassword: ""
    property bool notesVisible: false
    property string revealedNotes: ""
    property bool detailsVisible: false
    property var detailFields: []

    property string totpCode: ""
    property int totpSeconds: 30
    property string totpError: ""

    function clearSecrets() {
        revealedPassword = ""
        revealedNotes = ""
        detailFields = []
        notesVisible = false
        detailsVisible = false
        totpCode = ""
        totpError = ""
    }

    function groupedTotp(code) {
        if (code.length === 6) {
            return code.substring(0, 3) + " " + code.substring(3)
        }
        return code
    }

    function updateTotp() {
        var result = App.totpFor(itemId)
        if (result.error && result.error.length > 0) {
            totpError = result.error
            totpCode = ""
        } else {
            totpError = ""
            totpCode = result.code
            totpSeconds = result.seconds
        }
    }

    // The vault locking is the security-relevant event; this page only
    // reacts to it by dropping whatever it fetched. Belt-and-suspenders
    // with the top-level router, which also tears this page down when
    // App.state leaves "unlocked".
    Connections {
        target: App
        onStateChanged: {
            if (App.state !== "unlocked") { clearSecrets() }
        }
    }

    onStatusChanged: {
        if (status === PageStatus.Deactivating) { clearSecrets() }
    }

    Component.onDestruction: clearSecrets()

    Timer {
        interval: 1000
        repeat: true
        running: hasTotp && page.status === PageStatus.Active
        triggeredOnStart: true
        onTriggered: updateTotp()
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        PullDownMenu {
            MenuItem {
                text: qsTr("Copy name")
                onClicked: App.copyToClipboard(name)
            }
        }

        Column {
            id: column
            width: page.width
            spacing: Theme.paddingMedium

            PageHeader { title: name }

            // Username
            Item {
                width: parent.width
                height: Theme.itemSizeSmall
                visible: username.length > 0

                Column {
                    anchors {
                        left: parent.left
                        leftMargin: Theme.horizontalPageMargin
                        right: copyUsernameButton.left
                        rightMargin: Theme.paddingSmall
                        verticalCenter: parent.verticalCenter
                    }
                    Label {
                        width: parent.width
                        text: qsTr("Username")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                    Label {
                        width: parent.width
                        text: username
                        truncationMode: TruncationMode.Fade
                    }
                }

                IconButton {
                    id: copyUsernameButton
                    anchors {
                        right: parent.right
                        rightMargin: Theme.horizontalPageMargin
                        verticalCenter: parent.verticalCenter
                    }
                    icon.source: "image://theme/icon-m-clipboard"
                    onClicked: App.copyToClipboard(username)
                }
            }

            // Password
            Item {
                width: parent.width
                height: Theme.itemSizeSmall
                visible: hasPassword

                Column {
                    anchors {
                        left: parent.left
                        leftMargin: Theme.horizontalPageMargin
                        right: passwordButtons.left
                        rightMargin: Theme.paddingSmall
                        verticalCenter: parent.verticalCenter
                    }
                    Label {
                        width: parent.width
                        text: qsTr("Password")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                    Label {
                        width: parent.width
                        text: revealedPassword.length > 0 ? revealedPassword : "••••••••"
                        font.family: revealedPassword.length > 0 ? "monospace" : Theme.fontFamily
                        truncationMode: TruncationMode.Fade
                    }
                }

                Row {
                    id: passwordButtons
                    anchors {
                        right: parent.right
                        rightMargin: Theme.horizontalPageMargin
                        verticalCenter: parent.verticalCenter
                    }
                    spacing: Theme.paddingSmall

                    IconButton {
                        icon.source: revealedPassword.length > 0
                                     ? "image://theme/icon-m-shown"
                                     : "image://theme/icon-m-hidden"
                        onClicked: {
                            if (revealedPassword.length > 0) {
                                // Re-masking must also drop the plaintext —
                                // never just hide it visually.
                                revealedPassword = ""
                            } else {
                                revealedPassword = App.itemPassword(itemId)
                            }
                        }
                    }
                    IconButton {
                        icon.source: "image://theme/icon-m-clipboard"
                        // Copies without ever populating revealedPassword.
                        onClicked: App.copyToClipboard(App.itemPassword(itemId))
                    }
                }
            }

            // TOTP
            Item {
                width: parent.width
                height: totpColumn.height
                visible: hasTotp

                Column {
                    id: totpColumn
                    width: parent.width - Theme.horizontalPageMargin - copyTotpButton.width - Theme.paddingSmall
                    x: Theme.horizontalPageMargin

                    Label {
                        text: qsTr("Verification code")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                    Label {
                        text: totpError.length > 0 ? totpError : groupedTotp(totpCode)
                        font { family: "monospace"; pixelSize: Theme.fontSizeLarge }
                        color: totpError.length > 0 ? Theme.secondaryColor : Theme.primaryColor
                    }
                    ProgressBar {
                        width: parent.width
                        visible: totpError.length === 0
                        minimumValue: 0
                        // otpauth URIs may use periods longer than 30 s.
                        maximumValue: Math.max(30, totpSeconds)
                        value: totpSeconds
                        label: qsTr("%1 s").arg(totpSeconds)
                    }
                }

                IconButton {
                    id: copyTotpButton
                    anchors {
                        right: parent.right
                        rightMargin: Theme.horizontalPageMargin
                        top: parent.top
                        topMargin: Theme.paddingSmall
                    }
                    icon.source: "image://theme/icon-m-clipboard"
                    enabled: totpCode.length > 0
                    onClicked: App.copyToClipboard(totpCode)
                }
            }

            // URI
            Item {
                width: parent.width
                height: Theme.itemSizeSmall
                visible: uri.length > 0

                Column {
                    anchors {
                        left: parent.left
                        leftMargin: Theme.horizontalPageMargin
                        right: copyUriButton.left
                        rightMargin: Theme.paddingSmall
                        verticalCenter: parent.verticalCenter
                    }
                    Label {
                        width: parent.width
                        text: qsTr("Website")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                    Label {
                        width: parent.width
                        text: uri
                        truncationMode: TruncationMode.Fade
                    }
                }

                IconButton {
                    id: copyUriButton
                    anchors {
                        right: parent.right
                        rightMargin: Theme.horizontalPageMargin
                        verticalCenter: parent.verticalCenter
                    }
                    icon.source: "image://theme/icon-m-clipboard"
                    onClicked: App.copyToClipboard(uri)
                }
            }

            SectionHeader { text: qsTr("Notes") }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: notesVisible ? qsTr("Hide notes") : qsTr("Show notes")
                onClicked: {
                    if (notesVisible) {
                        revealedNotes = ""
                        notesVisible = false
                    } else {
                        revealedNotes = App.itemNotes(itemId)
                        notesVisible = true
                    }
                }
            }

            Label {
                visible: notesVisible
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                text: revealedNotes.length > 0 ? revealedNotes : qsTr("No notes")
                wrapMode: Text.WordWrap
                color: Theme.primaryColor
            }

            SectionHeader { text: qsTr("Details") }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: detailsVisible ? qsTr("Hide details") : qsTr("Show details")
                onClicked: {
                    if (detailsVisible) {
                        detailFields = []
                        detailsVisible = false
                    } else {
                        detailFields = App.itemDetailFields(itemId)
                        detailsVisible = true
                    }
                }
            }

            Repeater {
                model: detailsVisible ? detailFields : []
                delegate: Item {
                    width: column.width
                    height: Theme.itemSizeSmall

                    Column {
                        anchors {
                            left: parent.left
                            leftMargin: Theme.horizontalPageMargin
                            right: copyDetailButton.left
                            rightMargin: Theme.paddingSmall
                            verticalCenter: parent.verticalCenter
                        }
                        Label {
                            width: parent.width
                            text: modelData.name
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                        }
                        Label {
                            width: parent.width
                            text: modelData.value
                            truncationMode: TruncationMode.Fade
                        }
                    }

                    IconButton {
                        id: copyDetailButton
                        anchors {
                            right: parent.right
                            rightMargin: Theme.horizontalPageMargin
                            verticalCenter: parent.verticalCenter
                        }
                        icon.source: "image://theme/icon-m-clipboard"
                        onClicked: App.copyToClipboard(modelData.value)
                    }
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
