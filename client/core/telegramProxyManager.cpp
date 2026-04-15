#include "telegramProxyManager.h"

#include <QThread>

#include "telegramWsProxyEngine.h"

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
#endif

TelegramProxyManager::TelegramProxyManager(QObject *parent)
    : QObject(parent), m_statusText(tr("Stopped"))
{
    qRegisterMetaType<TelegramProxyRuntimeConfig>();
}

TelegramProxyManager::~TelegramProxyManager()
{
    stop();
    destroyEngineThread();
}

bool TelegramProxyManager::isRunning() const
{
    return m_running;
}

bool TelegramProxyManager::isBusy() const
{
    return m_busy;
}

QString TelegramProxyManager::statusText() const
{
    return m_statusText;
}

void TelegramProxyManager::start(const TelegramProxyRuntimeConfig &config)
{
    m_config = config;

    if (!m_engineThread) {
        m_engineThread = new QThread(this);
        m_engine = new TelegramWsProxyEngine();
        m_engine->moveToThread(m_engineThread);

        connect(m_engineThread, &QThread::finished, m_engine, &QObject::deleteLater);
        connect(m_engine, &TelegramWsProxyEngine::started, this, [this]() {
            setBusy(false);
            setRunning(true);
#ifdef Q_OS_ANDROID
            AndroidController::instance()->startTelegramProxyForegroundService(m_config.port);
#endif
        });
        connect(m_engine, &TelegramWsProxyEngine::stopped, this, [this]() {
            setBusy(false);
            setRunning(false);
            setStatusText(tr("Stopped"));
#ifdef Q_OS_ANDROID
            AndroidController::instance()->stopTelegramProxyForegroundService();
#endif
        });
        connect(m_engine, &TelegramWsProxyEngine::message, this, &TelegramProxyManager::message);
        connect(m_engine, &TelegramWsProxyEngine::errorOccurred, this, [this](const QString &errorMessage) {
            setBusy(false);
            setRunning(false);
            setStatusText(tr("Stopped"));
#ifdef Q_OS_ANDROID
            AndroidController::instance()->stopTelegramProxyForegroundService();
#endif
            emit errorOccurred(errorMessage);
        });
        connect(m_engine, &TelegramWsProxyEngine::statusTextChanged, this, &TelegramProxyManager::setStatusText);

        m_engineThread->start();
    }

    setBusy(true);
    setStatusText(tr("Starting..."));
    QMetaObject::invokeMethod(
            m_engine,
            [engine = m_engine, config]() {
                if (engine) {
                    engine->start(config);
                }
            },
            Qt::QueuedConnection);
}

void TelegramProxyManager::stop()
{
    if (!m_engineThread || !m_engine) {
        setBusy(false);
        setRunning(false);
        setStatusText(tr("Stopped"));
        return;
    }

    setBusy(true);
    setStatusText(tr("Stopping..."));
    QMetaObject::invokeMethod(m_engine, &TelegramWsProxyEngine::stop, Qt::QueuedConnection);
}

void TelegramProxyManager::setRunning(bool running)
{
    if (m_running == running) {
        return;
    }
    m_running = running;
    emit runningChanged(running);
}

void TelegramProxyManager::setBusy(bool busy)
{
    if (m_busy == busy) {
        return;
    }
    m_busy = busy;
    emit busyChanged(busy);
}

void TelegramProxyManager::setStatusText(const QString &statusText)
{
    if (m_statusText == statusText) {
        return;
    }
    m_statusText = statusText;
    emit statusTextChanged(statusText);
}

void TelegramProxyManager::destroyEngineThread()
{
    if (!m_engineThread) {
        return;
    }

    if (m_engine) {
        QMetaObject::invokeMethod(m_engine, &TelegramWsProxyEngine::stop, Qt::BlockingQueuedConnection);
    }

    m_engineThread->quit();
    m_engineThread->wait(1000);
    delete m_engineThread;
    m_engineThread = nullptr;
    m_engine = nullptr;
}
