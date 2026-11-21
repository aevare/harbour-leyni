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
        case "locked": return ["UnlockPage.qml"]
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
    //
    // Floats as a card below any display cutout (camera bump/notch).
    // Window children live in Silica's unrotated content item (only pages
    // rotate), so "top" here is always the physical top edge — the same
    // native-portrait space Screen.topCutout is reported in.
    Rectangle {
        id: noticeBanner

        readonly property int cutoutDepth: Screen.hasCutouts
            ? Screen.topCutout.y + Screen.topCutout.height : 0

        anchors {
            top: parent.top
            topMargin: cutoutDepth + Theme.paddingLarge
            horizontalCenter: parent.horizontalCenter
        }
        z: 1000
        width: parent.width - 2 * Theme.horizontalPageMargin
        height: noticeLabel.implicitHeight + Theme.paddingLarge * 2
        radius: Theme.paddingMedium
        // overlayBackgroundColor/primaryColor are the ambience's opposing
        // pair (dark/light or light/dark), so text contrast holds on any
        // ambience. Near-opaque so content scrolling underneath can't wash
        // it out; the accent border keeps it recognisably themed.
        color: Theme.rgba(Theme.overlayBackgroundColor, 0.95)
        border.color: Theme.rgba(Theme.highlightColor, 0.6)
        border.width: Math.max(1, Math.round(Theme.pixelRatio * 2))
        opacity: 0
        visible: opacity > 0.01

        Behavior on opacity { NumberAnimation { duration: 300 } }

        Label {
            id: noticeLabel
            anchors.centerIn: parent
            width: parent.width - 2 * Theme.paddingLarge
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            color: Theme.primaryColor
        }

        Timer {
            id: noticeTimer
            interval: 2500
            onTriggered: noticeBanner.opacity = 0
        }
    }

    // Top-bar spinner while the controller is busy (login/unlock KDF, sync,
    // writes); replaces the per-page BusyIndicators. Centered in the header
    // area so it doesn't collide with the left-aligned title or the pulley
    // arrow on the right.
    BusyIndicator {
        anchors {
            top: parent.top
            topMargin: noticeBanner.cutoutDepth + Theme.paddingSmall
            horizontalCenter: parent.horizontalCenter
        }
        z: 1001
        size: BusyIndicatorSize.Small
        running: App.busy
        visible: App.busy
    }
}
