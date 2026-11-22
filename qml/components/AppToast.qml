import QtQuick 2.0
import Sailfish.Silica 1.0

// Shows every App.notify() as a Toast. Last child of a Page/Dialog — inside
// the page so Silica lifts it above the keyboard.
Toast {
    id: toast

    Connections {
        target: App
        onNotify: toast.show(message, { variant: variant })
    }
}
