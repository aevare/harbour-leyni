import QtQuick 2.6
import Sailfish.Silica 1.0

// Cover MUST NEVER show item data — only app name, lock state, item count,
// and the two cover actions (doc/ARCHITECTURE.md).
CoverBackground {
    Column {
        anchors.centerIn: parent
        spacing: Theme.paddingSmall

        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "BitVault"
            font.pixelSize: Theme.fontSizeLarge
            color: Theme.primaryColor
        }

        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: App.state === "unlocked"
                  ? qsTr("%1 items unlocked").arg(App.itemCount)
                  : qsTr("Locked")
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.secondaryColor
        }
    }

    CoverActionList {
        CoverAction {
            visible: App.state === "unlocked"
            iconSource: "image://theme/icon-cover-refresh"
            onTriggered: App.syncNow()
        }
        CoverAction {
            visible: App.state === "unlocked"
            iconSource: "image://theme/icon-cover-cancel"
            onTriggered: App.lock()
        }
    }
}
