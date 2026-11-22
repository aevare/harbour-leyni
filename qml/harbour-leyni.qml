import QtQuick 2.6
import Sailfish.Silica 1.0
import "pages"

ApplicationWindow {
    id: window
    allowedOrientations: defaultAllowedOrientations
    cover: Qt.resolvedUrl("cover/CoverPage.qml")

    // Pure presentation routing — the state itself is decided in C++.
    function pageFileForState(state) {
        switch (state) {
        case "setup": return "pages/SetupPage.qml"
        case "login": return "pages/LoginPage.qml"
        case "twofactor": return "pages/TwoFactorPage.qml"
        case "locked": return "pages/UnlockPage.qml"
        default: return "pages/VaultPage.qml"
        }
    }

    // Pages allowed on the stack per state, by pageName — keeps
    // Settings/ItemDetail pushed while "unlocked".
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
            // Drop the stack — also runs onDestruction secret-clearing on
            // any lingering pages.
            pageStack.replaceAbove(null, Qt.resolvedUrl(pageFileForState(App.state)))
        }
    }

    // App.state is already final when QML loads — no splash page needed.
    initialPage: Qt.resolvedUrl(pageFileForState(App.state))

    Connections {
        target: App
        onStateChanged: routeState()
    }

    // Window children live in the unrotated content item: "top" is the
    // physical top edge (Screen.topCutout's space). Toasts are per-page
    // (components/AppToast.qml) so the keyboard lift applies to them.
    readonly property int cutoutDepth: Screen.hasCutouts
        ? Screen.topCutout.y + Screen.topCutout.height : 0

    // Busy spinner in the top bar; centered to clear the title and pulley arrow.
    BusyIndicator {
        anchors {
            top: parent.top
            topMargin: cutoutDepth + Theme.paddingSmall
            horizontalCenter: parent.horizontalCenter
        }
        z: 1001
        size: BusyIndicatorSize.Small
        running: App.busy
        visible: App.busy
    }
}
