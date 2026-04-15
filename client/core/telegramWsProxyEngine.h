#ifndef TELEGRAMWSPROXYENGINE_H
#define TELEGRAMWSPROXYENGINE_H

#include <QObject>
#include <QSet>

#include "core/telegramProxyTypes.h"

class QTcpServer;

class TelegramWsProxyEngine : public QObject
{
    Q_OBJECT

public:
    explicit TelegramWsProxyEngine(QObject *parent = nullptr);

public slots:
    void start(const TelegramProxyRuntimeConfig &config);
    void stop();

signals:
    void started();
    void stopped();
    void message(const QString &message);
    void errorOccurred(const QString &errorMessage);
    void statusTextChanged(const QString &statusText);

private:
    void onNewConnection();

    TelegramProxyRuntimeConfig m_config;
    QTcpServer *m_server = nullptr;
    QSet<QObject *> m_sessions;
    bool m_running = false;
};

#endif // TELEGRAMWSPROXYENGINE_H
