#include "telegramProxyController.h"

#include <algorithm>

#include <QDesktopServices>
#include <QRandomGenerator>
#include <QUrl>

namespace
{
    QString generateTelegramProxySecret()
    {
        QByteArray bytes(16, Qt::Uninitialized);
        for (int i = 0; i < bytes.size(); ++i) {
            bytes[i] = static_cast<char>(QRandomGenerator::system()->bounded(256));
        }
        return QString::fromLatin1(bytes.toHex());
    }
}

TelegramProxyController::TelegramProxyController(const std::shared_ptr<Settings> &settings, QObject *parent)
    : QObject(parent), m_settings(settings)
{
    connect(&m_manager, &TelegramProxyManager::runningChanged, this, &TelegramProxyController::runningChanged);
    connect(&m_manager, &TelegramProxyManager::busyChanged, this, &TelegramProxyController::busyChanged);
    connect(&m_manager, &TelegramProxyManager::statusTextChanged, this, &TelegramProxyController::statusTextChanged);
    connect(&m_manager, &TelegramProxyManager::message, this, &TelegramProxyController::message);
    connect(&m_manager, &TelegramProxyManager::errorOccurred, this, [this](const QString &errorMessage) {
        if (m_settings->isTelegramProxyEnabled()) {
            m_settings->setTelegramProxyEnabled(false);
            emit enabledChanged();
        }
        emit errorOccurred(errorMessage);
    });

    if (m_settings->isTelegramProxyEnabled() && isSupported()) {
        QMetaObject::invokeMethod(this, &TelegramProxyController::restart, Qt::QueuedConnection);
    }
}

bool TelegramProxyController::isSupported() const
{
#if defined(Q_OS_WIN) || defined(Q_OS_ANDROID)
    return true;
#else
    return false;
#endif
}

bool TelegramProxyController::isEnabled() const
{
    return m_settings->isTelegramProxyEnabled();
}

bool TelegramProxyController::isRunning() const
{
    return m_manager.isRunning();
}

bool TelegramProxyController::isBusy() const
{
    return m_manager.isBusy();
}

QString TelegramProxyController::getStatusText() const
{
    if (!isSupported()) {
        return tr("This feature is available only on Windows and Android");
    }
    return m_manager.statusText();
}

QString TelegramProxyController::getListenHost() const
{
    return m_settings->telegramProxyListenHost();
}

int TelegramProxyController::getPort() const
{
    return m_settings->telegramProxyPort();
}

QString TelegramProxyController::getSecret() const
{
    return m_settings->telegramProxySecret();
}

QString TelegramProxyController::getFakeTlsDomain() const
{
    return m_settings->telegramProxyFakeTlsDomain();
}

bool TelegramProxyController::isCfProxyEnabled() const
{
    return m_settings->isTelegramProxyCfProxyEnabled();
}

QString TelegramProxyController::getCfProxyDomain() const
{
    return m_settings->telegramProxyCfProxyDomain();
}

QString TelegramProxyController::getDdLink() const
{
    return QStringLiteral("tg://proxy?server=%1&port=%2&secret=dd%3")
            .arg(getListenHost())
            .arg(getPort())
            .arg(getSecret());
}

QString TelegramProxyController::getEeLink() const
{
    const QString domain = getFakeTlsDomain();
    if (domain.isEmpty()) {
        return QString();
    }

    return QStringLiteral("tg://proxy?server=%1&port=%2&secret=ee%3%4")
            .arg(getListenHost())
            .arg(getPort())
            .arg(getSecret())
            .arg(QString::fromLatin1(domain.toUtf8().toHex()));
}

QString TelegramProxyController::getPreferredLink() const
{
    const QString eeLink = getEeLink();
    return eeLink.isEmpty() ? getDdLink() : eeLink;
}

void TelegramProxyController::setEnabled(bool enabled)
{
    if (!isSupported()) {
        emit errorOccurred(tr("Telegram WS proxy is not supported on this platform"));
        return;
    }

    if (m_settings->isTelegramProxyEnabled() == enabled) {
        return;
    }

    m_settings->setTelegramProxyEnabled(enabled);
    emit enabledChanged();

    if (enabled) {
        restart();
    } else {
        m_manager.stop();
    }
}

void TelegramProxyController::setPort(int port)
{
    if (port <= 0 || port > 65535 || m_settings->telegramProxyPort() == port) {
        return;
    }

    m_settings->setTelegramProxyPort(port);
    emit portChanged();
    emit linksChanged();

    if (isEnabled()) {
        restart();
    }
}

void TelegramProxyController::setSecret(const QString &secret)
{
    const QString normalized = secret.trimmed().toLower();
    if (!isValidSecret(normalized)) {
        emit errorOccurred(tr("Secret must contain exactly 32 hex characters"));
        return;
    }

    if (m_settings->telegramProxySecret() == normalized) {
        return;
    }

    m_settings->setTelegramProxySecret(normalized);
    emit secretChanged();
    emit linksChanged();

    if (isEnabled()) {
        restart();
    }
}

void TelegramProxyController::regenerateSecret()
{
    setSecret(generateSecret());
}

void TelegramProxyController::setFakeTlsDomain(const QString &domain)
{
    const QString normalized = domain.trimmed().toLower();
    if (m_settings->telegramProxyFakeTlsDomain() == normalized) {
        return;
    }

    m_settings->setTelegramProxyFakeTlsDomain(normalized);
    emit fakeTlsDomainChanged();
    emit linksChanged();

    if (isEnabled()) {
        restart();
    }
}

void TelegramProxyController::setCfProxyEnabled(bool enabled)
{
    if (m_settings->isTelegramProxyCfProxyEnabled() == enabled) {
        return;
    }

    m_settings->setTelegramProxyCfProxyEnabled(enabled);
    emit cfProxyEnabledChanged();

    if (isEnabled()) {
        restart();
    }
}

void TelegramProxyController::setCfProxyDomain(const QString &domain)
{
    const QString normalized = domain.trimmed().toLower();
    if (m_settings->telegramProxyCfProxyDomain() == normalized) {
        return;
    }

    m_settings->setTelegramProxyCfProxyDomain(normalized);
    emit cfProxyDomainChanged();

    if (isEnabled()) {
        restart();
    }
}

void TelegramProxyController::openPreferredLink()
{
    QDesktopServices::openUrl(QUrl(getPreferredLink()));
}

void TelegramProxyController::restart()
{
    if (!isSupported()) {
        emit errorOccurred(tr("Telegram WS proxy is not supported on this platform"));
        return;
    }

    m_manager.start(runtimeConfig());
}

TelegramProxyRuntimeConfig TelegramProxyController::runtimeConfig() const
{
    TelegramProxyRuntimeConfig config;
    config.listenHost = getListenHost();
    config.port = static_cast<quint16>(getPort());
    config.secret = getSecret();
    config.fakeTlsDomain = getFakeTlsDomain();
    config.cfProxyDomain = getCfProxyDomain();
    config.cfProxyEnabled = isCfProxyEnabled();
    config.cfProxyPriorityEnabled = m_settings->isTelegramProxyCfProxyPriorityEnabled();
    return config;
}

bool TelegramProxyController::isValidSecret(const QString &secret) const
{
    if (secret.size() != 32) {
        return false;
    }

    return std::all_of(secret.cbegin(), secret.cend(), [](QChar c) {
        return c.isDigit() || (c >= QLatin1Char('a') && c <= QLatin1Char('f'));
    });
}

QString TelegramProxyController::generateSecret() const
{
    return generateTelegramProxySecret();
}

void TelegramProxyController::emitConfigChanged()
{
    emit portChanged();
    emit secretChanged();
    emit fakeTlsDomainChanged();
    emit cfProxyEnabledChanged();
    emit cfProxyDomainChanged();
    emit linksChanged();
}
