#include "settingsController.h"

#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QAbstractSocket>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QStandardPaths>
#include <QOperatingSystemVersion>
#include <algorithm>

#include "logger.h"
#include "core/networkUtilities.h"
#include "systemController.h"
#include "ui/qautostart.h"
#include "amnezia_application.h"
#include "version.h"
#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
    #include <QJniObject>
#endif

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    #include <AmneziaVPN-Swift.h>
#endif

SettingsController::SettingsController(const QSharedPointer<ServersModel> &serversModel,
                                       const QSharedPointer<ContainersModel> &containersModel,
                                       const QSharedPointer<LanguageModel> &languageModel,
                                       const QSharedPointer<SitesModel> &sitesModel,
                                       const QSharedPointer<AppSplitTunnelingModel> &appSplitTunnelingModel,
                                       const std::shared_ptr<Settings> &settings, QObject *parent)
    : QObject(parent),
      m_serversModel(serversModel),
      m_containersModel(containersModel),
      m_languageModel(languageModel),
      m_sitesModel(sitesModel),
      m_appSplitTunnelingModel(appSplitTunnelingModel),
      m_settings(settings)
{
    m_appVersion = QString("%1 (%2, %3)").arg(QString(APP_VERSION), __DATE__, GIT_COMMIT_HASH);
    checkIfNeedDisableLogs();
#ifdef Q_OS_ANDROID
    connect(AndroidController::instance(), &AndroidController::notificationStateChanged, this, &SettingsController::onNotificationStateChanged);
    connect(AndroidController::instance(), &AndroidController::imeInsetsChanged, this, [this](int heightDp) {
        m_imeHeight = heightDp;
        emit imeHeightChanged(heightDp);
        emit safeAreaBottomMarginChanged();
    });
    connect(AndroidController::instance(), &AndroidController::systemBarsInsetsChanged, this, [this](int navBarHeightDp, int statusBarHeightDp) {
        m_cachedNavigationBarHeight = navBarHeightDp;
        m_cachedStatusBarHeight = statusBarHeightDp;
        emit safeAreaBottomMarginChanged();
        emit safeAreaTopMarginChanged();
    });
    connect(AndroidController::instance(), &AndroidController::activityPaused, this, &SettingsController::activityPaused);
    connect(AndroidController::instance(), &AndroidController::activityResumed, this, &SettingsController::activityResumed);
#endif

    m_isDevModeEnabled = m_settings->isDevGatewayEnv();
    toggleDevGatewayEnv(m_isDevModeEnabled);

    if (m_settings->isRuBypassEnabled() && !isRuBypassSupported()) {
        toggleRuBypass(false);
    } else if (m_settings->isRuBypassEnabled()) {
        ensureRuBypassRouteSetAvailable();
        refreshRuBypassRouteSetIfNeeded();
    }
}

QString getPlatformName()
{
#if defined(Q_OS_WINDOWS)
    return "Windows";
#elif defined(Q_OS_ANDROID)
    return "Android";
#elif defined(Q_OS_LINUX)
    return "Linux";
#elif defined(Q_OS_MACX)
    return "MacOS";
#elif defined(Q_OS_IOS)
    return "iOS";
#else
    return "Unknown";
#endif
}

namespace
{
    constexpr auto ruBypassRouteSetResource = ":/route-sets/ru_ipv4.json";
    constexpr auto ruBypassRouteSetUrl = "https://stat.ripe.net/data/country-resource-list/data.json?resource=ru&v4_format=prefix";
    constexpr int ruBypassRouteSetMaxAgeDays = 7;

#ifdef Q_OS_ANDROID
    constexpr int androidTiramisuApiLevel = 33;
#endif

    struct Ipv4Cidr
    {
        quint32 network = 0;
        int prefix = 32;
    };

    quint32 ipv4Mask(const int prefix)
    {
        if (prefix <= 0) {
            return 0;
        }
        if (prefix >= 32) {
            return 0xffffffffu;
        }

        return 0xffffffffu << (32 - prefix);
    }

    bool contains(const Ipv4Cidr &lhs, const Ipv4Cidr &rhs)
    {
        if (lhs.prefix > rhs.prefix) {
            return false;
        }

        return (rhs.network & ipv4Mask(lhs.prefix)) == lhs.network;
    }

    bool canMerge(const Ipv4Cidr &lhs, const Ipv4Cidr &rhs)
    {
        if (lhs.prefix != rhs.prefix || lhs.prefix <= 0) {
            return false;
        }

        const quint64 blockSize = quint64(1) << (32 - lhs.prefix);
        const quint32 parentMask = ipv4Mask(lhs.prefix - 1);
        return lhs.network < rhs.network
               && quint64(lhs.network) + blockSize == rhs.network
               && (lhs.network & parentMask) == lhs.network;
    }

    QString ipv4CidrToString(const Ipv4Cidr &cidr)
    {
        return QString("%1/%2").arg(QHostAddress(cidr.network).toString()).arg(cidr.prefix);
    }

    QStringList collapseIpv4Routes(const QStringList &routes)
    {
        QVector<Ipv4Cidr> parsedRoutes;
        parsedRoutes.reserve(routes.size());

        for (const QString &route : routes) {
            const QStringList parts = route.split('/');
            const QHostAddress address(parts.first());
            if (address.protocol() != QAbstractSocket::IPv4Protocol) {
                continue;
            }

            bool ok = false;
            const int prefix = parts.size() > 1 ? parts.last().toInt(&ok) : 32;
            if (!ok && parts.size() > 1) {
                continue;
            }

            parsedRoutes.push_back({ address.toIPv4Address() & ipv4Mask(prefix), prefix });
        }

        std::sort(parsedRoutes.begin(), parsedRoutes.end(), [](const Ipv4Cidr &lhs, const Ipv4Cidr &rhs) {
            if (lhs.network == rhs.network) {
                return lhs.prefix < rhs.prefix;
            }
            return lhs.network < rhs.network;
        });

        QVector<Ipv4Cidr> collapsedRoutes;
        collapsedRoutes.reserve(parsedRoutes.size());
        for (const Ipv4Cidr &route : parsedRoutes) {
            if (!collapsedRoutes.isEmpty()) {
                if (collapsedRoutes.constLast().network == route.network
                    && collapsedRoutes.constLast().prefix == route.prefix) {
                    continue;
                }
                if (contains(collapsedRoutes.constLast(), route)) {
                    continue;
                }
            }

            while (!collapsedRoutes.isEmpty() && contains(route, collapsedRoutes.constLast())) {
                collapsedRoutes.removeLast();
            }

            collapsedRoutes.push_back(route);

            while (collapsedRoutes.size() >= 2) {
                const Ipv4Cidr &rhs = collapsedRoutes.constLast();
                const Ipv4Cidr &lhs = collapsedRoutes.at(collapsedRoutes.size() - 2);
                if (!canMerge(lhs, rhs)) {
                    break;
                }

                collapsedRoutes.removeLast();
                collapsedRoutes.removeLast();
                collapsedRoutes.push_back({ lhs.network & ipv4Mask(lhs.prefix - 1), lhs.prefix - 1 });
            }
        }

        QStringList result;
        result.reserve(collapsedRoutes.size());
        for (const Ipv4Cidr &route : collapsedRoutes) {
            result.append(ipv4CidrToString(route));
        }

        return result;
    }

    QStringList parseRuBypassRoutes(const QByteArray &payload, QString *queryTime = nullptr)
    {
        QJsonParseError parseError;
        const QJsonDocument doc = QJsonDocument::fromJson(payload, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            qWarning() << "Failed to parse RU bypass route set:" << parseError.errorString();
            return {};
        }

        const QJsonObject root = doc.object();
        QString parsedQueryTime;
        QJsonArray routesArray;

        if (root.contains("ipv4")) {
            parsedQueryTime = root.value("query_time").toString();
            routesArray = root.value("ipv4").toArray();
        } else {
            const QJsonObject dataObject = root.value("data").toObject();
            parsedQueryTime = dataObject.value("query_time").toString();
            routesArray = dataObject.value("resources").toObject().value("ipv4").toArray();
        }

        QStringList routes;
        routes.reserve(routesArray.size());
        for (const QJsonValue &value : routesArray) {
            if (!value.isString()) {
                continue;
            }

            const QString route = value.toString().trimmed();
            if (!NetworkUtilities::checkIpSubnetFormat(route)) {
                continue;
            }

            routes.append(route);
        }

        routes.removeDuplicates();
        routes = collapseIpv4Routes(routes);
        if (queryTime != nullptr) {
            *queryTime = parsedQueryTime;
        }

        return routes;
    }

    QString formatRouteSetDate(const QString &queryTime)
    {
        if (queryTime.isEmpty()) {
            return {};
        }

        const QDateTime queryDateTime = QDateTime::fromString(queryTime, Qt::ISODate);
        if (!queryDateTime.isValid()) {
            return queryTime;
        }

        return queryDateTime.toString("yyyy-MM-dd");
    }
}

void SettingsController::toggleAmneziaDns(bool enable)
{
    m_settings->setUseAmneziaDns(enable);
    emit amneziaDnsToggled(enable);
}

bool SettingsController::isAmneziaDnsEnabled()
{
    return m_settings->useAmneziaDns();
}

QString SettingsController::getPrimaryDns()
{
    return m_settings->primaryDns();
}

void SettingsController::setPrimaryDns(const QString &dns)
{
    m_settings->setPrimaryDns(dns);
    emit primaryDnsChanged();
}

QString SettingsController::getSecondaryDns()
{
    return m_settings->secondaryDns();
}

void SettingsController::setSecondaryDns(const QString &dns)
{
    return m_settings->setSecondaryDns(dns);
    emit secondaryDnsChanged();
}

bool SettingsController::isLoggingEnabled()
{
    return m_settings->isSaveLogs();
}

void SettingsController::toggleLogging(bool enable)
{
    m_settings->setSaveLogs(enable);
#if defined(Q_OS_IOS)
    AmneziaVPN::toggleLogging(enable);
#endif
    if (enable == true) {
        qInfo().noquote() << QString("Logging has enabled on %1 version %2 %3").arg(APPLICATION_NAME, APP_VERSION, GIT_COMMIT_HASH);
        qInfo().noquote() << QString("%1 (%2)").arg(QSysInfo::prettyProductName(), QSysInfo::currentCpuArchitecture());
    }
    emit loggingStateChanged();
}

void SettingsController::openLogsFolder()
{
    Logger::openLogsFolder(false);
}

void SettingsController::openServiceLogsFolder()
{
    Logger::openLogsFolder(true);
}

void SettingsController::exportLogsFile(const QString &fileName)
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->exportLogsFile(fileName);
#else
    SystemController::saveFile(fileName, Logger::getLogFile());
#endif
}

void SettingsController::exportServiceLogsFile(const QString &fileName)
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->exportLogsFile(fileName);
#else
    SystemController::saveFile(fileName, Logger::getServiceLogFile());
#endif
}

void SettingsController::clearLogs()
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->clearLogs();
#else
    Logger::clearLogs(false);
    Logger::clearServiceLogs();
#endif

    qInfo().noquote() << QString("Started %1 version %2 %3").arg(APPLICATION_NAME, APP_VERSION, GIT_COMMIT_HASH);
    qInfo().noquote() << QString("%1 (%2)").arg(QSysInfo::prettyProductName(), QSysInfo::currentCpuArchitecture());
    qInfo().noquote() << QString("SSL backend: %1").arg(QSslSocket::sslLibraryVersionString());
}

void SettingsController::backupAppConfig(const QString &fileName)
{
    QByteArray data = m_settings->backupAppConfig();
    QJsonDocument doc = QJsonDocument::fromJson(data);
    QJsonObject config = doc.object();

    config["AppPlatform"] = getPlatformName();
    config["Conf/autoStart"] = Autostart::isAutostart();
    config["Conf/killSwitchEnabled"] = isKillSwitchEnabled();
    config["Conf/strictKillSwitchEnabled"] = isStrictKillSwitchEnabled();
    config["Conf/useAmneziaDns"] = isAmneziaDnsEnabled();

    SystemController::saveFile(fileName, QJsonDocument(config).toJson());
}

void SettingsController::restoreAppConfig(const QString &fileName)
{
    QByteArray data;
    if (!SystemController::readFile(fileName, data)) {
        emit changeSettingsErrorOccurred(tr("Can't open file: %1").arg(fileName));
        return;
    }
    restoreAppConfigFromData(data);
}

void SettingsController::restoreAppConfigFromData(const QByteArray &data)
{
    bool ok = m_settings->restoreAppConfig(data);
    if (ok) {
        QJsonObject newConfigData = QJsonDocument::fromJson(data).object();

#if defined(Q_OS_WINDOWS) || defined(Q_OS_LINUX) || defined(Q_OS_MACX)
        bool autoStart = false;
        if (newConfigData.contains("Conf/autoStart")) {
            autoStart = newConfigData["Conf/autoStart"].toBool();
        }
        toggleAutoStart(autoStart);
#endif

        m_serversModel->resetModel();
        m_languageModel->changeLanguage(
                static_cast<LanguageSettings::AvailableLanguageEnum>(m_languageModel->getCurrentLanguageIndex()));

#if defined(Q_OS_WINDOWS) || defined(Q_OS_ANDROID)
        int appSplitTunnelingRouteMode = newConfigData.value("Conf/appsRouteMode").toInt();
        bool appSplittunnelingEnabled =
                newConfigData.value("Conf/appsSplitTunnelingEnabled").toVariant().toString().toLower() == "true";
        m_appSplitTunnelingModel->setRouteMode(appSplitTunnelingRouteMode);

        #if defined(Q_OS_WINDOWS)
            m_appSplitTunnelingModel->setRouteMode(static_cast<int>(Settings::AppsRouteMode::VpnAllExceptApps));
        #endif

        if (newConfigData.contains("AppPlatform")) { //if backup is from a new version
                if (newConfigData.value("AppPlatform").toString() != getPlatformName()) {
                    m_appSplitTunnelingModel->clearAppsList();
                }
        }
        
        m_appSplitTunnelingModel->toggleSplitTunneling(appSplittunnelingEnabled);
#endif

        int siteSplitTunnelingRouteMode = newConfigData.value("Conf/routeMode").toInt();
        bool siteSplittunnelingEnabled =
                newConfigData.value("Conf/sitesSplitTunnelingEnabled").toVariant().toString().toLower() == "true";
        m_sitesModel->setRouteMode(siteSplitTunnelingRouteMode);
        m_sitesModel->toggleSplitTunneling(siteSplittunnelingEnabled);

        if (m_settings->isRuBypassEnabled() && !isRuBypassSupported()) {
            toggleRuBypass(false);
        } else if (m_settings->isRuBypassEnabled()) {
            ensureRuBypassRouteSetAvailable();
            refreshRuBypassRouteSetIfNeeded();
        }
        emit ruBypassChanged();

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
        m_settings->setAutoConnect(false);
        m_settings->setStartMinimized(false);
        m_settings->setKillSwitchEnabled(false);
        m_settings->setStrictKillSwitchEnabled(false);
#endif

        bool amneziaDnsEnabled = newConfigData.contains("Conf/useAmneziaDns")
                                     ? newConfigData.value("Conf/useAmneziaDns").toBool()
                                     : m_settings->useAmneziaDns();
        emit amneziaDnsToggled(amneziaDnsEnabled);

        emit restoreBackupFinished();
    } else {
        emit changeSettingsErrorOccurred(tr("Backup file is corrupted"));
    }
}

QString SettingsController::getAppVersion()
{
    return m_appVersion;
}

void SettingsController::clearSettings()
{
    m_settings->clearSettings();
    m_serversModel->resetModel();
    m_languageModel->changeLanguage(m_languageModel->getSystemLanguageEnum());

    m_sitesModel->setRouteMode(Settings::RouteMode::VpnOnlyForwardSites);
    m_sitesModel->toggleSplitTunneling(false);

    m_appSplitTunnelingModel->setRouteMode(Settings::AppsRouteMode::VpnAllExceptApps);
    m_appSplitTunnelingModel->toggleSplitTunneling(false);

    toggleAutoStart(false);
    emit ruBypassChanged();

    emit changeSettingsFinished(tr("All settings have been reset to default values"));

#if defined(Q_OS_IOS) || defined(MACOS_NE)
    AmneziaVPN::clearSettings();
#endif
}

bool SettingsController::isAutoConnectEnabled()
{
    return m_settings->isAutoConnect();
}

void SettingsController::toggleAutoConnect(bool enable)
{
    m_settings->setAutoConnect(enable);
}

bool SettingsController::isAutoStartEnabled()
{
    return Autostart::isAutostart();
}

void SettingsController::toggleAutoStart(bool enable)
{
    Autostart::setAutostart(enable);
    if (!enable) {
        toggleStartMinimized(false);
    }
}

bool SettingsController::isStartMinimizedEnabled()
{
    return m_settings->isStartMinimized();
}

void SettingsController::toggleStartMinimized(bool enable)
{
    m_settings->setStartMinimized(enable);
    emit startMinimizedChanged();
}

bool SettingsController::isNewsNotificationsEnabled()
{
    return m_settings->isNewsNotifications();
}
void SettingsController::toggleNewsNotificationsEnabled(bool enable)
{
    m_settings->setNewsNotifications(enable);
}

bool SettingsController::isScreenshotsEnabled()
{
    return m_settings->isScreenshotsEnabled();
}

void SettingsController::toggleScreenshotsEnabled(bool enable)
{
    m_settings->setScreenshotsEnabled(enable);
}

bool SettingsController::isCameraPresent()
{
#if defined Q_OS_IOS
    return true;
#elif defined Q_OS_ANDROID
    return AndroidController::instance()->isCameraPresent();
#else
    return false;
#endif
}

void SettingsController::checkIfNeedDisableLogs()
{
    if (m_settings->isSaveLogs()) {
        m_loggingDisableDate = m_settings->getLogEnableDate().addDays(14);
        if (m_loggingDisableDate <= QDateTime::currentDateTime()) {
            toggleLogging(false);
            clearLogs();
            emit loggingDisableByWatcher();
        }
    }
}

bool SettingsController::isKillSwitchEnabled()
{
    return m_settings->isKillSwitchEnabled();
}

void SettingsController::toggleKillSwitch(bool enable)
{
    m_settings->setKillSwitchEnabled(enable);
    emit killSwitchEnabledChanged();
    if (enable == false) {
        emit strictKillSwitchEnabledChanged(false);
    } else {
        emit strictKillSwitchEnabledChanged(isStrictKillSwitchEnabled());
    }
}

bool SettingsController::isStrictKillSwitchEnabled()
{
    return m_settings->isStrictKillSwitchEnabled();
}

void SettingsController::toggleStrictKillSwitch(bool enable)
{
    m_settings->setStrictKillSwitchEnabled(enable);
    emit strictKillSwitchEnabledChanged(enable);
}

bool SettingsController::isRuBypassEnabled()
{
    return m_settings->isRuBypassEnabled();
}

void SettingsController::toggleRuBypass(bool enable)
{
    if (enable == m_settings->isRuBypassEnabled()) {
        return;
    }

    if (enable) {
        if (!isRuBypassSupported()) {
#ifdef Q_OS_ANDROID
            emit ruBypassErrorOccurred(tr("Bypass Russian resources requires Android 13 or newer"));
#else
            emit ruBypassErrorOccurred(tr("Bypass Russian resources is not supported on this platform"));
#endif
            emit ruBypassChanged();
            return;
        }

        if (!ensureRuBypassRouteSetAvailable()) {
            emit ruBypassErrorOccurred(tr("Failed to load the Russian route set"));
            emit ruBypassChanged();
            return;
        }

        m_settings->storeRuBypassSiteSplitState(m_settings->isSitesSplitTunnelingEnabled(), m_settings->routeMode());
        m_settings->setRuBypassEnabled(true);
        m_sitesModel->setRouteMode(Settings::RouteMode::VpnAllExceptSites);
        m_sitesModel->toggleSplitTunneling(true);

        emit ruBypassChanged();
        emit ruBypassMessage(tr("Bypass Russian resources enabled"));
        refreshRuBypassRouteSetIfNeeded();
        return;
    }

    m_settings->setRuBypassEnabled(false);
    if (m_settings->hasStoredRuBypassSiteSplitState()) {
        m_sitesModel->setRouteMode(m_settings->storedRuBypassRouteMode());
        m_sitesModel->toggleSplitTunneling(m_settings->storedRuBypassSitesSplitTunnelingEnabled());
        m_settings->clearStoredRuBypassSiteSplitState();
    }

    emit ruBypassChanged();
    emit ruBypassMessage(tr("Bypass Russian resources disabled"));
}

bool SettingsController::isRuBypassSupported()
{
#if defined(Q_OS_WINDOWS)
    return true;
#elif defined(Q_OS_ANDROID)
    // Pre-Android 13 excluded routes are expanded into included routes, which
    // makes the RU preset too large to apply safely.
    return QJniObject::getStaticField<jint>("android/os/Build$VERSION", "SDK_INT") >= androidTiramisuApiLevel;
#else
    return false;
#endif
}

bool SettingsController::isRuBypassUpdating()
{
    return m_ruBypassUpdateInProgress;
}

QString SettingsController::getRuBypassStatusText()
{
#ifdef Q_OS_ANDROID
    if (!isRuBypassSupported()) {
        return tr("Routes Russian IPv4 resources outside the VPN. Available on Android 13 or newer.");
    }
#endif

    const QString routeSetDate = formatRouteSetDate(m_settings->ruBypassRouteSetQueryTime());
    if (m_ruBypassUpdateInProgress) {
        return tr("Routes Russian IPv4 resources outside the VPN. Updating route set...");
    }
    if (!routeSetDate.isEmpty()) {
        return tr("Routes Russian IPv4 resources outside the VPN. Route set date: %1").arg(routeSetDate);
    }
    return tr("Routes Russian IPv4 resources outside the VPN.");
}

bool SettingsController::isNotificationPermissionGranted()
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->isNotificationPermissionGranted();
#else
    return true;
#endif
}

void SettingsController::requestNotificationPermission()
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->requestNotificationPermission();
#endif
}

QString SettingsController::getInstallationUuid()
{
    return m_settings->getInstallationUuid(false);
}

void SettingsController::enableDevMode()
{
    m_isDevModeEnabled = true;
    emit devModeEnabled();
}

bool SettingsController::isDevModeEnabled()
{
    return m_isDevModeEnabled;
}

void SettingsController::resetGatewayEndpoint()
{
    m_settings->resetGatewayEndpoint();
    emit gatewayEndpointChanged(m_settings->getGatewayEndpoint());
}

void SettingsController::setGatewayEndpoint(const QString &endpoint)
{
    m_settings->setGatewayEndpoint(endpoint);
    emit gatewayEndpointChanged(endpoint);
}

QString SettingsController::getGatewayEndpoint()
{
    return m_settings->isDevGatewayEnv() ? "Dev endpoint" : m_settings->getGatewayEndpoint();
}

bool SettingsController::isDevGatewayEnv()
{
    return m_settings->isDevGatewayEnv();
}

void SettingsController::toggleDevGatewayEnv(bool enabled)
{
    m_settings->toggleDevGatewayEnv(enabled);
    if (enabled) {
        m_settings->setDevGatewayEndpoint();
    } else {
        m_settings->resetGatewayEndpoint();
    }
    emit gatewayEndpointChanged(m_settings->getGatewayEndpoint());
    emit devGatewayEnvChanged(enabled);
}

bool SettingsController::isOnTv()
{
#ifdef Q_OS_ANDROID
    return AndroidController::instance()->isOnTv();
#else
    return false;
#endif
}

bool SettingsController::isEdgeToEdgeEnabled()
{
#ifdef Q_OS_ANDROID
    if (!m_edgeToEdgeCached) {
        m_cachedEdgeToEdgeEnabled = AndroidController::instance()->isEdgeToEdgeEnabled();
        m_edgeToEdgeCached = true;
    }
    return m_cachedEdgeToEdgeEnabled;
#else
    return false;
#endif
}

int SettingsController::getStatusBarHeight()
{
#ifdef Q_OS_ANDROID
    if (m_cachedStatusBarHeight < 0) {
        m_cachedStatusBarHeight = AndroidController::instance()->getStatusBarHeight();
    }
    return m_cachedStatusBarHeight;
#else
    return 0;
#endif
}

int SettingsController::getNavigationBarHeight()
{
#ifdef Q_OS_ANDROID
    if (m_cachedNavigationBarHeight < 0) {
        m_cachedNavigationBarHeight = AndroidController::instance()->getNavigationBarHeight();
    }
    return m_cachedNavigationBarHeight;
#else
    return 0;
#endif
}

int SettingsController::getSafeAreaTopMargin()
{
#ifdef Q_OS_ANDROID
    if (isEdgeToEdgeEnabled()) {
        int height = getStatusBarHeight();
        int result = height > 0 ? height : 40; // fallback to 40 if system returns 0
        return result;
    }
#endif
    return 0;
}

int SettingsController::getSafeAreaBottomMargin()
{
#ifdef Q_OS_ANDROID
    if (isEdgeToEdgeEnabled()) {
        if (m_imeHeight > 0) {
            return 0;
        }
        
        int height = getNavigationBarHeight();
        int result = height > 0 ? height : 56; // fallback to 56 if system returns 0
        return result;
    }
#endif
    return 0;
}

int SettingsController::getImeHeight()
{
    return m_imeHeight;
}

bool SettingsController::isHomeAdLabelVisible()
{
    return m_settings->isHomeAdLabelVisible();
}

void SettingsController::disableHomeAdLabel()
{
    m_settings->disableHomeAdLabel();
    emit isHomeAdLabelVisibleChanged(false);
}

bool SettingsController::ensureRuBypassRouteSetAvailable()
{
    if (!m_settings->ruBypassRoutes().isEmpty()) {
        return true;
    }

    return loadBundledRuBypassRouteSet();
}

bool SettingsController::loadBundledRuBypassRouteSet()
{
    QFile routeSetFile(ruBypassRouteSetResource);
    if (!routeSetFile.open(QIODevice::ReadOnly)) {
        qWarning() << "Failed to open bundled RU bypass route set";
        return false;
    }

    QString queryTime;
    const QStringList routes = parseRuBypassRoutes(routeSetFile.readAll(), &queryTime);
    if (routes.isEmpty()) {
        qWarning() << "Bundled RU bypass route set is empty";
        return false;
    }

    m_settings->setRuBypassRoutes(routes);
    m_settings->setRuBypassRouteSetQueryTime(queryTime);
    m_settings->setRuBypassRouteSetUpdatedAt(QDateTime());
    return true;
}

void SettingsController::refreshRuBypassRouteSetIfNeeded(bool force)
{
    if (!isRuBypassSupported() || m_ruBypassUpdateInProgress) {
        return;
    }

    const QDateTime updatedAt = m_settings->ruBypassRouteSetUpdatedAt();
    if (!force && updatedAt.isValid()
        && updatedAt.daysTo(QDateTime::currentDateTimeUtc()) < ruBypassRouteSetMaxAgeDays) {
        return;
    }

    m_ruBypassUpdateInProgress = true;
    emit ruBypassUpdatingChanged();
    emit ruBypassChanged();

    QNetworkRequest request(QUrl(QString::fromLatin1(ruBypassRouteSetUrl)));
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

    QNetworkReply *reply = amnApp->networkManager()->get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();

        m_ruBypassUpdateInProgress = false;
        emit ruBypassUpdatingChanged();
        emit ruBypassChanged();

        if (reply->error() != QNetworkReply::NoError) {
            qWarning() << "Failed to update RU bypass route set:" << reply->errorString();
            if (m_settings->isRuBypassEnabled()) {
                emit ruBypassMessage(tr("Using the bundled Russian route set"));
            }
            return;
        }

        QString queryTime;
        const QStringList routes = parseRuBypassRoutes(reply->readAll(), &queryTime);
        if (routes.isEmpty()) {
            emit ruBypassErrorOccurred(tr("Failed to parse the updated Russian route set"));
            return;
        }

        m_settings->setRuBypassRoutes(routes);
        if (!queryTime.isEmpty()) {
            m_settings->setRuBypassRouteSetQueryTime(queryTime);
        }
        m_settings->setRuBypassRouteSetUpdatedAt(QDateTime::currentDateTimeUtc());

        emit ruBypassChanged();
        emit ruBypassMessage(tr("Russian route set updated"));
    });
}
