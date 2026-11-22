import QtQuick 2.6
import Sailfish.Silica 1.0

// Cover MUST NEVER show item data — only lock state and item count
// (doc/ARCHITECTURE.md).
CoverBackground {
    Column {
        anchors.centerIn: parent
        spacing: Theme.paddingSmall

        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: "Leyni"
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

    // CoverAction has no `visible` on SFOS — gate the list with `enabled`.
    CoverActionList {
        enabled: App.state === "unlocked"

        CoverAction {
            iconSource: "image://theme/icon-cover-refresh"
            onTriggered: App.syncNow()
        }
        CoverAction {
            iconSource: "image://theme/icon-cover-cancel"
            onTriggered: App.lock()
        }
    }
}
