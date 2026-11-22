import QtQuick 2.0
import Sailfish.Silica 1.0

// Message icons, kind: info | success | error | delete | close | offline |
// lock | sync. themeIcon (default) uses the Sailfish icon tinted via
// "?color"; kinds the theme lacks (offline) fall back to a drawn 24-unit
// stroke icon. https://sailfishos.org/develop/docs/jolla-ambient/
Item {
    id: root

    property string kind: "info"
    property color color: Theme.primaryColor
    property bool themeIcon: true
    property real strokeWidth: 1.6

    readonly property var _themeNames: ({
        "info": "icon-m-about",
        "success": "icon-m-acknowledge",
        "error": "icon-m-warning",
        "delete": "icon-m-delete",
        "close": "icon-m-dismiss",
        "lock": "icon-m-device-lock",
        "sync": "icon-m-sync"
    })
    readonly property string _themeName: themeIcon && _themeNames[kind] ? _themeNames[kind] : ""

    width: Theme.iconSizeMedium
    height: width

    Image {
        id: image

        anchors.fill: parent
        visible: root._themeName.length > 0
        source: visible ? "image://theme/" + root._themeName + "?" + root.color : ""
        sourceSize.width: width
        sourceSize.height: height
        fillMode: Image.PreserveAspectFit
    }

    // Theme icons have padding inside their box; shrink the drawn ones to match.
    Canvas {
        id: canvas

        anchors.centerIn: parent
        width: parent.width * 0.75
        height: width
        visible: !image.visible

        onVisibleChanged: requestPaint()
        onWidthChanged: requestPaint()
        onHeightChanged: requestPaint()

        Connections {
            target: root
            onKindChanged: canvas.requestPaint()
            onColorChanged: canvas.requestPaint()
        }

        onPaint: {
            var ctx = getContext("2d")
            ctx.reset()
            ctx.scale(width / 24, height / 24)
            ctx.strokeStyle = root.color
            ctx.lineWidth = root.strokeWidth
            ctx.lineCap = "round"
            ctx.lineJoin = "round"
            ctx.beginPath()

            switch (root.kind) {
            case "success":
                ctx.moveTo(5, 12.5); ctx.lineTo(9.5, 17); ctx.lineTo(19, 7)
                break
            case "error":
                ctx.moveTo(12, 3.5); ctx.lineTo(21, 19.5); ctx.lineTo(3, 19.5); ctx.closePath()
                ctx.moveTo(12, 10); ctx.lineTo(12, 14.5)
                ctx.moveTo(12, 17.2); ctx.lineTo(12, 17.3)
                break
            case "delete":
                ctx.moveTo(4, 7); ctx.lineTo(20, 7)
                ctx.moveTo(9, 7); ctx.lineTo(9, 4); ctx.lineTo(15, 4); ctx.lineTo(15, 7)
                ctx.moveTo(6, 7); ctx.lineTo(7, 20); ctx.lineTo(17, 20); ctx.lineTo(18, 7)
                break
            case "close":
                ctx.moveTo(6, 6); ctx.lineTo(18, 18)
                ctx.moveTo(18, 6); ctx.lineTo(6, 18)
                break
            case "offline":
                ctx.moveTo(17.5, 18); ctx.lineTo(7, 18)
                ctx.arc(7, 14, 4, Math.PI / 2, Math.PI * 1.5, false)
                ctx.arc(12, 10, 5, Math.PI, 0, false)
                ctx.arc(17.5, 14, 4, -Math.PI / 2, Math.PI / 2, false)
                ctx.moveTo(3, 3); ctx.lineTo(21, 21)
                break
            case "lock":
                ctx.rect(5, 11, 14, 10)
                ctx.moveTo(8, 11); ctx.lineTo(8, 7)
                ctx.arc(12, 7, 4, Math.PI, 0, false)
                ctx.lineTo(16, 11)
                break
            case "sync":
                ctx.arc(12, 12, 8, -0.15, Math.PI / 4, true)
                ctx.moveTo(20, 5); ctx.lineTo(20, 11); ctx.lineTo(14, 11)
                break
            default: // info
                ctx.arc(12, 12, 9, 0, Math.PI * 2, false)
                ctx.moveTo(12, 11); ctx.lineTo(12, 17)
                ctx.moveTo(12, 7.5); ctx.lineTo(12, 7.6)
                break
            }

            ctx.stroke()
        }
    }
}
