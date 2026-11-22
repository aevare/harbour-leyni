import QtQuick 2.0
import Sailfish.Silica 1.0

// Flat text button for toast/banner actions.
MouseArea {
    id: root

    property alias text: label.text
    property color color: Theme.highlightColor
    property bool primary: true

    width: label.implicitWidth + 2 * Theme.paddingLarge
    height: Theme.itemSizeExtraSmall

    Rectangle {
        anchors.fill: parent
        radius: Theme.paddingSmall
        color: Theme.rgba(Theme.highlightBackgroundColor, Theme.highlightBackgroundOpacity)
        visible: root.pressed && root.containsMouse
    }

    Label {
        id: label

        anchors.centerIn: parent
        color: root.pressed && root.containsMouse ? Theme.highlightColor
                                                  : (root.primary ? root.color : Theme.primaryColor)
        font.pixelSize: Theme.fontSizeSmall
        font.bold: root.primary
    }
}
