#ifndef TELEGRAMPROXYCONTROLLER_H
#define TELEGRAMPROXYCONTROLLER_H

#include <QObject>

#include "core/telegramProxyManager.h"
#include "settings.h"

class TelegramProxyController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isSupported READ isSupported CONSTANT)
    Q_PROPERTY(bool enabled READ isEnabled WRITE setEnabled NOTIFY enabledChanged)
    Q_PROPERTY(bool running READ isRunning NOTIFY runningChanged)
    Q_PROPERTY(bool busy READ isBusy NOTIFY busyChanged)
    Q_PROPERTY(QString statusText READ getStatusText NOTIFY statusTextChanged)
    Q_PROPERTY(QString listenHost READ getListenHost NOTIFY listenHostChanged)
    Q_PROPERTY(int port READ getPort WRITE setPort NOTIFY portChanged)
    Q_PROPERTY(QString secret READ getSecret WRITE setSecret NOTIFY secretChanged)
    Q_PROPERTY(QString fakeTlsDomain READ getFakeTlsDomain WRITE setFakeTlsDomain NOTIFY fakeTlsDomainChanged)
    Q_PROPERTY(bool cfProxyEnabled READ isCfProxyEnabled WRITE setCfProxyEnabled NOTIFY cfProxyEnabledChanged)
    Q_PROPERTY(QString cfProxyDomain READ getCfProxyDomain WRITE setCfProxyDomain NOTIFY cfProxyDomainChanged)
    Q_PROPERTY(QString ddLink READ getDdLink NOTIFY linksChanged)
    Q_PROPERTY(QString eeLink READ getEeLink NOTIFY linksChanged)
    Q_PROPERTY(QString preferredLink READ getPreferredLink NOTIFY linksChanged)

public:
    explicit TelegramProxyController(const std::shared_ptr<Settings> &settings, QObject *parent = nullptr);

    bool isSupported() const;
    bool isEnabled() const;
    bool isRunning() const;
    bool isBusy() const;
    QString getStatusText() const;
    QString getListenHost() const;
    int getPort() const;
    QString getSecret() const;
    QString getFakeTlsDomain() const;
    bool isCfProxyEnabled() const;
    QString getCfProxyDomain() const;
    QString getDdLink() const;
    QString getEeLink() const;
    QString getPreferredLink() const;

public slots:
    void setEnabled(bool enabled);
    void setPort(int port);
    void setSecret(const QString &secret);
    void regenerateSecret();
    void setFakeTlsDomain(const QString &domain);
    void setCfProxyEnabled(bool enabled);
    void setCfProxyDomain(const QString &domain);
    void openPreferredLink();
    void restart();

signals:
    void enabledChanged();
    void runningChanged();
    void busyChanged();
    void statusTextChanged();
    void listenHostChanged();
    void portChanged();
    void secretChanged();
    void fakeTlsDomainChanged();
    void cfProxyEnabledChanged();
    void cfProxyDomainChanged();
    void linksChanged();
    void message(const QString &message);
    void errorOccurred(const QString &errorMessage);

private:
    TelegramProxyRuntimeConfig runtimeConfig() const;
    bool isValidSecret(const QString &secret) const;
    QString generateSecret() const;
    void emitConfigChanged();

    std::shared_ptr<Settings> m_settings;
    TelegramProxyManager m_manager;
};

#endif // TELEGRAMPROXYCONTROLLER_H
