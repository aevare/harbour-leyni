import QtQuick 2.6
import Sailfish.Silica 1.0
import "pages"

ApplicationWindow {
    id: window
    allowedOrientations: defaultAllowedOrientations
    cover: Qt.resolvedUrl("cover/CoverPage.qml")

    // Maps an App.state value to the QML file (relative to qml/) that is
    // its "home" page. Pure presentation routing — no security decisions
    // are made here, the state itself is decided entirely in C++.
    function pageFileForState(state) {
        switch (state) {
        case "setup": return "pages/SetupPage.qml"
        case "login": return "pages/LoginPage.qml"
        case "twofactor": return "pages/TwoFactorPage.qml"
        case "locked": return "pages/UnlockPage.qml"
        default: return "pages/VaultPage.qml"
        }
    }

    // Pages that are allowed to remain on the stack while App.state has
    // this value (identified by each page's own `pageName` property).
    // This lets SettingsPage/ItemDetailPage stay pushed while "unlocked"
    // instead of being torn down on every unrelated state notification.
    function pageFamilyForState(state) {
        switch (state) {
        case "setup": return ["SetupPage.qml"]
        case "login": return ["LoginPage.qml", "SetupPage.qml"]
        case "twofactor": return ["TwoFactorPage.qml"]
        case "locked": return ["UnlockPage.qml", "SettingsPage.qml"]
        case "unlocked": return ["VaultPage.qml", "ItemDetailPage.qml", "ItemEditPage.qml", "GeneratorDialog.qml", "SettingsPage.qml"]
        default: return ["SetupPage.qml"]
        }
    }

    function routeState() {
        var family = pageFamilyForState(App.state)
        var current = pageStack.currentPage
        var currentName = (current && current.pageName) ? current.pageName : ""
        if (family.indexOf(currentName) === -1) {
            // Current top page does not belong to the new state (e.g. the
            // vault just locked while ItemDetailPage was open) — drop the
            // whole stack and land on the state's home page. This also
            // destroys any lingering pages, running their onDestruction
            // secret-clearing handlers.
            pageStack.replaceAbove(null, Qt.resolvedUrl(pageFileForState(App.state)))
        }
    }

    // App.state already holds its real value by the time QML loads, so the
    // very first page can be resolved directly — no placeholder/splash page
    // needed.
    initialPage: Qt.resolvedUrl(pageFileForState(App.state))

    Connections {
        target: App
        onStateChanged: routeState()
        onNotify: {
            noticeLabel.text = message
            noticeBanner.opacity = 1
            noticeTimer.restart()
        }
    }

    // Transient in-app notice banner for App.notify(). Kept local to the
    // window (no system notification dependency) since these are one-shot
    // hints like "Copied — clears in 30 s", not events worth a Notification
    // center entry.
    Rectangle {
        id: noticeBanner
        anchors {
            top: parent.top
            left: parent.left
            right: parent.right
        }
        z: 1000
        height: noticeLabel.implicitHeight + Theme.paddingMedium * 2
        color: Theme.rgba(Theme.highlightBackgroundColor, 0.95)
        opacity: 0
        visible: opacity > 0.01

        Behavior on opacity { NumberAnimation { duration: 300 } }

        Label {
            id: noticeLabel
            anchors.centerIn: parent
            width: parent.width - 2 * Theme.horizontalPageMargin
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: Theme.highlightColor
        }

        Timer {
            id: noticeTimer
            interval: 2500
            onTriggered: noticeBanner.opacity = 0
        }
    }
}
