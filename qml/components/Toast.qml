import QtQuick 2.0
import Sailfish.Silica 1.0
import "MessageStyle.js" as Style

// In-app toast: short feedback about what the user just did. Last child of a
// Page; call show(title, { variant, body, actionText, onAction, onExpired }).
// variant: info | success | error | warning | undo. One at a time (rest queue);
// 3 s, 6 s with an action; swipe or × dismisses. Sits above the keyboard
// (Silica shrinks the page) and above the bottom edge (set bottomInset).
Item {
    id: root

    property real bottomInset: 0
    property int shortDuration: 3000
    property int actionDuration: 6000
    // Standard Sailfish icons (true) or the drawn ones from the design canvas.
    property bool themeIcons: true

    readonly property bool active: _current !== null

    // The message being shown (kept while it slides out).
    property var _display: ({ title: "", body: "", variant: "info", actionText: "" })
    // The message that is live; null while sliding out or idle.
    property var _current: null
    property var _queue: []
    property real _slide: 0
    property real _swipe: 0
    property real _progress: 1

    // No keyboard term: Silica shrinks the page while the keyboard is open.
    readonly property real _lift: bottomInset

    readonly property color _tone: Style.tone(Theme, _display.variant, Theme.colorScheme === Theme.LightOnDark)

    function show(title, options) {
        var o = options || {}
        var msg = {
            title: title,
            body: o.body || "",
            variant: o.variant || "info",
            icon: o.icon || Style.icon(o.variant || "info"),
            actionText: o.actionText || "",
            onAction: o.onAction,
            onExpired: o.onExpired,
            duration: o.duration || (o.actionText ? actionDuration : shortDuration)
        }

        if (_current && !_current.actionText && !msg.actionText
                && _current.title === msg.title && _current.body === msg.body) {
            timerAnimation.restart()
            return
        }

        if (_current || hideAnimation.running) {
            var queue = _queue
            queue.push(msg)
            _queue = queue
            return
        }
        _present(msg)
    }

    function dismiss() {
        _finish(false)
    }

    function clear() {
        _queue = []
        _finish(false)
    }

    function _present(msg) {
        _display = msg
        _current = msg
        _swipe = 0
        _progress = 1
        timerAnimation.duration = msg.duration
        showAnimation.restart()
        timerAnimation.restart()
    }

    function _finish(actionTriggered) {
        var msg = _current
        if (!msg)
            return
        _current = null
        timerAnimation.stop()
        swipeBack.stop()
        showAnimation.stop()
        hideAnimation.restart()

        if (actionTriggered) {
            if (msg.onAction)
                msg.onAction()
        } else if (msg.onExpired) {
            msg.onExpired()
        }
    }

    function _next() {
        if (_current || _queue.length === 0)
            return
        var queue = _queue
        var msg = queue.shift()
        _queue = queue
        _present(msg)
    }

    function _setPaused(paused) {
        if (!timerAnimation.running)
            return
        if (paused)
            timerAnimation.pause()
        else
            timerAnimation.resume()
    }

    anchors.fill: parent
    z: 200

    NumberAnimation {
        id: showAnimation
        target: root; property: "_slide"; to: 1
        duration: 220; easing.type: Easing.OutCubic
    }

    NumberAnimation {
        id: hideAnimation
        target: root; property: "_slide"; to: 0
        duration: 180; easing.type: Easing.InCubic
        onStopped: if (root._slide === 0) root._next()
    }

    NumberAnimation {
        id: swipeBack
        target: root; property: "_swipe"; to: 0
        duration: 200; easing.type: Easing.OutCubic
    }

    NumberAnimation {
        id: timerAnimation
        target: root; property: "_progress"; from: 1; to: 0
        onStopped: if (root._progress <= 0 && root._current) root._finish(false)
    }

    Connections {
        target: Qt.application
        onActiveChanged: root._setPaused(!Qt.application.active || cardArea.pressed)
    }

    // Soft shadow — no drop shadow without QtGraphicalEffects (not Harbour-allowed).
    Rectangle {
        x: card.x
        y: card.y + Theme.paddingSmall
        width: card.width
        height: card.height
        radius: card.radius
        color: "black"
        opacity: 0.25 * card.opacity
        visible: card.visible
    }

    Rectangle {
        id: card

        readonly property real restY: root.height - root._lift - Theme.paddingLarge - height

        x: Theme.paddingMedium + root._swipe
        y: restY + (1 - root._slide) * (height + Theme.paddingLarge)
        width: root.width - 2 * Theme.paddingMedium
        height: Math.max(Theme.itemSizeMedium, Math.max(textColumn.height, Theme.itemSizeExtraSmall) + 2 * Theme.paddingMedium)
        opacity: root._slide * (1 - Math.min(1, Math.abs(root._swipe) / width))
        visible: root._slide > 0
        radius: Theme.paddingSmall
        color: Theme.rgba(Theme.overlayBackgroundColor, 0.9)
        border.width: 1
        border.color: Theme.rgba(Theme.primaryColor, 0.12)

        Rectangle {
            anchors.fill: parent
            radius: parent.radius
            color: Theme.rgba(Theme.highlightBackgroundColor, 0.1)
        }

        // Pauses the timer while touched; swipe sideways dismisses.
        MouseArea {
            id: cardArea

            property real _startX

            anchors.fill: parent

            onPressed: {
                swipeBack.stop()
                _startX = mapToItem(root, mouse.x, 0).x - root._swipe
            }
            onPositionChanged: root._swipe = mapToItem(root, mouse.x, 0).x - _startX
            onReleased: {
                if (Math.abs(root._swipe) > card.width / 3)
                    root._finish(false)
                else
                    swipeBack.restart()
            }
            onCanceled: swipeBack.restart()
            onPressedChanged: root._setPaused(pressed || !Qt.application.active)
        }

        MessageIcon {
            id: icon

            x: Theme.paddingLarge
            anchors.verticalCenter: parent.verticalCenter
            kind: root._display.icon || "info"
            color: root._tone
            themeIcon: root.themeIcons
        }

        Column {
            id: textColumn

            anchors {
                left: icon.right
                leftMargin: Theme.paddingMedium
                right: trailing.left
                verticalCenter: parent.verticalCenter
            }

            Label {
                width: parent.width
                text: root._display.title
                color: Theme.primaryColor
                font.pixelSize: Theme.fontSizeSmall
                font.bold: true
                wrapMode: Text.Wrap
            }

            Label {
                width: parent.width
                visible: text.length > 0
                text: root._display.body
                color: Theme.secondaryColor
                font.pixelSize: Theme.fontSizeExtraSmall
                wrapMode: Text.Wrap
            }
        }

        Item {
            id: trailing

            anchors.right: parent.right
            anchors.rightMargin: Theme.paddingSmall
            anchors.verticalCenter: parent.verticalCenter
            width: actionButton.visible ? actionButton.width : closeButton.width
            height: Theme.itemSizeExtraSmall

            TextButton {
                id: actionButton

                visible: root._display.actionText.length > 0
                text: root._display.actionText
                color: Style.actionColor(Theme, root._display.variant)
                onClicked: root._finish(true)
            }

            MouseArea {
                id: closeButton

                visible: !actionButton.visible
                width: Theme.itemSizeExtraSmall
                height: Theme.itemSizeExtraSmall
                onClicked: root._finish(false)

                MessageIcon {
                    anchors.centerIn: parent
                    kind: "close"
                    themeIcon: root.themeIcons
                    color: closeButton.pressed ? Theme.highlightColor : Theme.secondaryColor
                }
            }
        }

        Rectangle {
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            anchors.leftMargin: parent.radius / 2
            width: (parent.width - parent.radius) * root._progress
            height: Math.max(2, Math.round(2 * Theme.pixelRatio))
            color: root._tone
            opacity: 0.7
        }
    }
}
