import QtQuick 2.0
import Sailfish.Silica 1.0
import "MessageStyle.js" as Style

// Lasting page state (offline, missing permission, failed sync): under the
// PageHeader in the page's Column, stays until `shown` clears — no close
// button. variant: info | warning | error.
Item {
    id: root

    property string variant: "info"
    // MessageIcon kind; defaults to one that fits the variant.
    property string icon: Style.icon(variant)
    property string title
    property string text
    property string actionText
    property string secondaryText
    property bool shown: true
    // Standard Sailfish icons (true) or the drawn ones from the design canvas.
    property bool themeIcons: true

    signal actionClicked()
    signal secondaryClicked()

    readonly property color _tone: Style.tone(Theme, variant, Theme.colorScheme === Theme.LightOnDark)

    width: parent ? parent.width : 0
    height: shown ? card.height + 2 * Theme.paddingSmall : 0
    opacity: shown ? 1 : 0
    visible: height > 0
    clip: true

    Behavior on height {
        NumberAnimation { duration: 200; easing.type: Easing.InOutQuad }
    }
    Behavior on opacity {
        FadeAnimation {}
    }

    Rectangle {
        id: card

        x: Theme.paddingMedium
        y: Theme.paddingSmall
        width: parent.width - 2 * x
        height: content.y + content.height + (buttons.visible ? Theme.paddingSmall : Theme.paddingMedium)
        radius: Theme.paddingSmall
        color: Theme.rgba(Theme.primaryColor, 0.07)
        border.width: 1
        border.color: Theme.rgba(Theme.primaryColor, 0.07)

        Column {
            id: content

            x: Theme.paddingLarge
            y: Theme.paddingMedium
            width: parent.width - 2 * x

            Row {
                width: parent.width
                spacing: Theme.paddingMedium

                MessageIcon {
                    id: icon

                    kind: root.icon
                    color: root._tone
                    themeIcon: root.themeIcons
                }

                Column {
                    width: parent.width - icon.width - parent.spacing
                    spacing: Theme.paddingSmall / 2

                    Label {
                        width: parent.width
                        text: root.title
                        color: Theme.primaryColor
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true
                        wrapMode: Text.Wrap
                    }

                    Label {
                        width: parent.width
                        visible: text.length > 0
                        text: root.text
                        color: Theme.secondaryColor
                        font.pixelSize: Theme.fontSizeExtraSmall
                        wrapMode: Text.Wrap
                    }
                }
            }

            Row {
                id: buttons

                anchors.right: parent.right
                anchors.rightMargin: -Theme.paddingMedium
                visible: root.actionText.length > 0 || root.secondaryText.length > 0

                TextButton {
                    visible: root.secondaryText.length > 0
                    text: root.secondaryText
                    primary: false
                    onClicked: root.secondaryClicked()
                }

                TextButton {
                    visible: root.actionText.length > 0
                    text: root.actionText
                    color: root._tone
                    onClicked: root.actionClicked()
                }
            }
        }
    }
}
