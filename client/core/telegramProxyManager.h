#ifndef TELEGRAMPROXYMANAGER_H
#define TELEGRAMPROXYMANAGER_H

#include <QObject>
#include <QString>

#include "core/telegramProxyTypes.h"

class QThread;
class TelegramWsProxyEngine;

class TelegramProxyManager : public QObject
{
    Q_OBJECT

public:
    explicit TelegramProxyManager(QObject *parent = nullptr);
    ~TelegramProxyManager() override;

    bool isRunning() const;
    bool isBusy() const;
    QString statusText() const;

public slots:
    void start(const TelegramProxyRuntimeConfig &config);
    void stop();

signals:
    void runningChanged(bool running);
    void busyChanged(bool busy);
    void statusTextChanged(const QString &statusText);
    void errorOccurred(const QString &errorMessage);
    void message(const QString &message);

private:
    void setRunning(bool running);
    void setBusy(bool busy);
    void setStatusText(const QString &statusText);
    void destroyEngineThread();

    TelegramProxyRuntimeConfig m_config;
    TelegramWsProxyEngine *m_engine = nullptr;
    QThread *m_engineThread = nullptr;
    bool m_running = false;
    bool m_busy = false;
    QString m_statusText;
};

#endif // TELEGRAMPROXYMANAGER_H
