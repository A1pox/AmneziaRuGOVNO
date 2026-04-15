import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import Style 1.0

import "./"
import "../Controls2"
import "../Config"

PageType {
    id: root

    Connections {
        target: TelegramProxyController

        function onMessage(message) {
            PageController.showNotificationMessage(message)
        }

        function onErrorOccurred(errorMessage) {
            PageController.showErrorMessage(errorMessage)
        }
    }

    BackButtonType {
        id: backButton

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 20 + SettingsController.safeAreaTopMargin

        onActiveFocusChanged: {
            if (backButton.enabled && backButton.activeFocus) {
                listView.positionViewAtBeginning()
            }
        }
    }

    ListViewType {
        id: listView

        anchors.top: backButton.bottom
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right

        header: ColumnLayout {
            width: listView.width

            BaseHeaderType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Telegram WS proxy")
                descriptionText: qsTr("Runs a local MTProto proxy that forwards Telegram traffic through Telegram WebSocket endpoints.")
            }
        }

        model: 1

        delegate: ColumnLayout {
            width: listView.width

            SwitcherType {
                Layout.fillWidth: true
                Layout.margins: 16

                text: qsTr("Enable Telegram WS proxy")
                descriptionText: TelegramProxyController.statusText

                checked: TelegramProxyController.enabled
                enabled: TelegramProxyController.isSupported && !TelegramProxyController.busy

                onToggled: function() {
                    if (checked !== TelegramProxyController.enabled) {
                        TelegramProxyController.enabled = checked
                    }
                }
            }

            DividerType {}

            LabelWithButtonType {
                Layout.fillWidth: true

                text: qsTr("Host")
                descriptionText: TelegramProxyController.listenHost
                descriptionOnTop: true
                rightImageSource: "qrc:/images/controls/copy.svg"
                rightImageColor: AmneziaStyle.color.paleGray

                clickedFunction: function() {
                    GC.copyToClipBoard(descriptionText)
                    PageController.showNotificationMessage(qsTr("Copied"))
                }
            }

            DividerType {}

            TextFieldWithHeaderType {
                id: portField

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 16
                Layout.bottomMargin: 16

                enabled: !TelegramProxyController.busy
                headerText: qsTr("Port")
                textField.text: TelegramProxyController.port
                textField.maximumLength: 5
                textField.validator: IntValidator { bottom: 1; top: 65535 }

                textField.onEditingFinished: {
                    textField.text = textField.text.replace(/^\s+|\s+$/g, "")
                    if (textField.text !== "" && Number(textField.text) !== TelegramProxyController.port) {
                        TelegramProxyController.port = Number(textField.text)
                    }
                }
            }

            TextFieldWithHeaderType {
                id: secretField

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                enabled: !TelegramProxyController.busy
                headerText: qsTr("Secret")
                textField.text: TelegramProxyController.secret
                textField.maximumLength: 32
                buttonImageSource: "qrc:/images/controls/refresh-cw.svg"

                clickedFunc: function() {
                    TelegramProxyController.regenerateSecret()
                    textField.text = TelegramProxyController.secret
                }

                textField.onEditingFinished: {
                    textField.text = textField.text.replace(/^\s+|\s+$/g, "").toLowerCase()
                    if (textField.text !== TelegramProxyController.secret) {
                        TelegramProxyController.secret = textField.text
                    }
                }
            }

            TextFieldWithHeaderType {
                id: fakeTlsField

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                enabled: !TelegramProxyController.busy
                headerText: qsTr("Fake TLS domain")
                textField.placeholderText: "example.com"
                textField.text: TelegramProxyController.fakeTlsDomain

                textField.onEditingFinished: {
                    textField.text = textField.text.replace(/^\s+|\s+$/g, "").toLowerCase()
                    if (textField.text !== TelegramProxyController.fakeTlsDomain) {
                        TelegramProxyController.fakeTlsDomain = textField.text
                    }
                }
            }

            SwitcherType {
                Layout.fillWidth: true
                Layout.margins: 16

                text: qsTr("Use Cloudflare fallback")
                descriptionText: qsTr("Falls back to CF proxied WebSocket domains when direct Telegram WS fails")

                checked: TelegramProxyController.cfProxyEnabled
                enabled: !TelegramProxyController.busy

                onToggled: function() {
                    if (checked !== TelegramProxyController.cfProxyEnabled) {
                        TelegramProxyController.cfProxyEnabled = checked
                    }
                }
            }

            DividerType {}

            TextFieldWithHeaderType {
                id: cfDomainField

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                enabled: !TelegramProxyController.busy
                headerText: qsTr("Custom CF domain")
                textField.placeholderText: "cdn.example.com"
                textField.text: TelegramProxyController.cfProxyDomain

                textField.onEditingFinished: {
                    textField.text = textField.text.replace(/^\s+|\s+$/g, "").toLowerCase()
                    if (textField.text !== TelegramProxyController.cfProxyDomain) {
                        TelegramProxyController.cfProxyDomain = textField.text
                    }
                }
            }

            LabelWithButtonType {
                Layout.fillWidth: true

                text: qsTr("Connection link")
                descriptionText: TelegramProxyController.preferredLink
                descriptionOnTop: true
                rightImageSource: "qrc:/images/controls/copy.svg"
                rightImageColor: AmneziaStyle.color.paleGray

                clickedFunction: function() {
                    GC.copyToClipBoard(descriptionText)
                    PageController.showNotificationMessage(qsTr("Copied"))
                }
            }

            DividerType {}

            LabelWithButtonType {
                Layout.fillWidth: true

                text: qsTr("Open in Telegram")
                descriptionText: qsTr("Passes the generated tg://proxy link to Telegram")
                rightImageSource: "qrc:/images/controls/external-link.svg"

                clickedFunction: function() {
                    TelegramProxyController.openPreferredLink()
                }
            }

            DividerType {}
        }
    }
}
