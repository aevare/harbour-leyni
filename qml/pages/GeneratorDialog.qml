import QtQuick 2.6
import Sailfish.Silica 1.0

// Random password generator. All generation happens in C++ (App.generatePassword
// → the audited crypto core); this dialog only chooses options and displays the
// result. The caller reads `password` on `accepted`.
Dialog {
    id: dialog
    allowedOrientations: Orientation.All
    readonly property string pageName: "GeneratorDialog.qml"

    property string password: ""
    property string acceptText: qsTr("Use")   // "Use" (fill a field) or "Copy"

    // Guards regeneration during initial property setup.
    property bool ready: false

    readonly property bool hasClass: upperSwitch.checked || lowerSwitch.checked
                                     || digitSwitch.checked || symbolSwitch.checked
    canAccept: hasClass && password.length > 0

    function currentOptions() {
        return {
            "length": Math.round(lengthSlider.value),
            "lowercase": lowerSwitch.checked,
            "uppercase": upperSwitch.checked,
            "digits": digitSwitch.checked,
            "symbols": symbolSwitch.checked,
            "avoidAmbiguous": ambiguousSwitch.checked
        }
    }

    function regenerate() {
        password = hasClass ? App.generatePassword(currentOptions()) : ""
    }

    Component.onCompleted: {
        var o = App.generatorOptions()
        lengthSlider.value = o.length
        upperSwitch.checked = o.uppercase
        lowerSwitch.checked = o.lowercase
        digitSwitch.checked = o.digits
        symbolSwitch.checked = o.symbols
        ambiguousSwitch.checked = o.avoidAmbiguous
        regenerate()
        ready = true
    }

    onAccepted: App.setGeneratorOptions(currentOptions())

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingMedium

            DialogHeader {
                title: qsTr("Generate password")
                acceptText: dialog.acceptText
            }

            Item {
                width: parent.width
                height: Math.max(pwLabel.implicitHeight, regenButton.height)
                        + Theme.paddingMedium

                Label {
                    id: pwLabel
                    anchors {
                        left: parent.left
                        leftMargin: Theme.horizontalPageMargin
                        right: regenButton.left
                        rightMargin: Theme.paddingSmall
                        verticalCenter: parent.verticalCenter
                    }
                    text: password.length > 0
                          ? password
                          : qsTr("Enable a character type")
                    font {
                        family: "monospace"
                        pixelSize: Theme.fontSizeMedium
                    }
                    wrapMode: Text.WrapAnywhere
                    color: password.length > 0 ? Theme.highlightColor
                                               : Theme.secondaryColor
                }

                IconButton {
                    id: regenButton
                    anchors {
                        right: parent.right
                        rightMargin: Theme.horizontalPageMargin
                        verticalCenter: parent.verticalCenter
                    }
                    icon.source: "image://theme/icon-m-refresh"
                    onClicked: regenerate()
                }
            }

            Slider {
                id: lengthSlider
                width: parent.width
                minimumValue: 5
                maximumValue: 64
                stepSize: 1
                value: 16
                label: qsTr("Length")
                valueText: Math.round(value).toString()
                onValueChanged: if (dialog.ready) { regenerate() }
            }

            TextSwitch {
                id: upperSwitch
                text: qsTr("Uppercase (A–Z)")
                onCheckedChanged: if (dialog.ready) { regenerate() }
            }
            TextSwitch {
                id: lowerSwitch
                text: qsTr("Lowercase (a–z)")
                onCheckedChanged: if (dialog.ready) { regenerate() }
            }
            TextSwitch {
                id: digitSwitch
                text: qsTr("Digits (0–9)")
                onCheckedChanged: if (dialog.ready) { regenerate() }
            }
            TextSwitch {
                id: symbolSwitch
                text: qsTr("Symbols (!@#$…)")
                onCheckedChanged: if (dialog.ready) { regenerate() }
            }
            TextSwitch {
                id: ambiguousSwitch
                text: qsTr("Avoid ambiguous (I l 1 O 0 o)")
                onCheckedChanged: if (dialog.ready) { regenerate() }
            }
        }

        VerticalScrollDecorator {}
    }
}
