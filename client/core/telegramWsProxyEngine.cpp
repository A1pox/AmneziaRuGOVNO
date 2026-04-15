#include "telegramWsProxyEngine.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <utility>

#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QMessageAuthenticationCode>
#include <QPointer>
#include <QRandomGenerator>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslSocket>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QtEndian>

#include <openssl/evp.h>

namespace
{
constexpr int kHandshakeLen = 64;
constexpr int kSkipLen = 8;
constexpr int kPreKeyLen = 32;
constexpr int kKeyLen = 32;
constexpr int kIvLen = 16;
constexpr int kProtoTagPos = 56;
constexpr int kDcIdxPos = 60;

constexpr quint8 kTlsRecordHandshake = 0x16;
constexpr quint8 kTlsRecordChangeCipherSpec = 0x14;
constexpr quint8 kTlsRecordApplicationData = 0x17;
constexpr quint32 kTimestampToleranceSeconds = 120;
constexpr int kTlsAppDataMax = 16384;
constexpr int kSocketBufferSize = 256 * 1024;

const QByteArray kProtoTagAbridged("\xEF\xEF\xEF\xEF", 4);
const QByteArray kProtoTagIntermediate("\xEE\xEE\xEE\xEE", 4);
const QByteArray kProtoTagSecure("\xDD\xDD\xDD\xDD", 4);

const quint32 kProtoAbridgedInt = 0xEFEFEFEF;
const quint32 kProtoIntermediateInt = 0xEEEEEEEE;
const quint32 kProtoPaddedIntermediateInt = 0xDDDDDDDD;

const QByteArray kReservedContinue("\x00\x00\x00\x00", 4);
const QList<QByteArray> kReservedStarts = {
    QByteArray("HEAD", 4),
    QByteArray("POST", 4),
    QByteArray("GET ", 4),
    QByteArray("\xEE\xEE\xEE\xEE", 4),
    QByteArray("\xDD\xDD\xDD\xDD", 4),
    QByteArray("\x16\x03\x01\x02", 4),
};

const QMap<int, QString> kDefaultDcFallbackIps = {
    { 1, QStringLiteral("149.154.175.50") },
    { 2, QStringLiteral("149.154.167.51") },
    { 3, QStringLiteral("149.154.175.100") },
    { 4, QStringLiteral("149.154.167.91") },
    { 5, QStringLiteral("149.154.171.5") },
    { 203, QStringLiteral("91.105.192.100") },
};

const QMap<int, QString> kDefaultWsTargetIps = {
    { 2, QStringLiteral("149.154.167.220") },
    { 4, QStringLiteral("149.154.167.220") },
};

const QStringList kDefaultCfProxyDomains = {
    QStringLiteral("pclead.co.uk"),
    QStringLiteral("offshor.co.uk"),
    QStringLiteral("cakeisalie.co.uk"),
    QStringLiteral("noskomnadzor.co.uk"),
    QStringLiteral("lovetrue.co.uk"),
};

enum class FallbackMethod {
    CfProxy,
    Tcp,
};

QByteArray randomBytes(const int size)
{
    QByteArray bytes(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i) {
        bytes[i] = static_cast<char>(QRandomGenerator::system()->bounded(256));
    }
    return bytes;
}

QByteArray sha256(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    return QMessageAuthenticationCode::hash(data, key, QCryptographicHash::Sha256);
}

QByteArray reverseByteArray(QByteArray data)
{
    std::reverse(data.begin(), data.end());
    return data;
}

void setSocketOptions(QAbstractSocket *socket)
{
    if (!socket) {
        return;
    }

    socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, kSocketBufferSize);
    socket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, kSocketBufferSize);
}

QStringList wsDomains(int dc, bool isMedia)
{
    if (dc == 203) {
        dc = 2;
    }

    if (isMedia) {
        return {
            QStringLiteral("kws%1-1.web.telegram.org").arg(dc),
            QStringLiteral("kws%1.web.telegram.org").arg(dc),
        };
    }

    return {
        QStringLiteral("kws%1.web.telegram.org").arg(dc),
        QStringLiteral("kws%1-1.web.telegram.org").arg(dc),
    };
}

QString fallbackTcpIp(int dc)
{
    return kDefaultDcFallbackIps.value(dc);
}

QByteArray buildServerHelloTemplate()
{
    QByteArray data;
    data.append(QByteArray::fromHex("160303007a020000760303"));
    data.append(QByteArray(32, '\0'));
    data.append(char(0x20));
    data.append(QByteArray(32, '\0'));
    data.append(QByteArray::fromHex("130100002e00330024001d0020"));
    data.append(QByteArray(32, '\0'));
    data.append(QByteArray::fromHex("002b00020304"));
    return data;
}

QByteArray xorMask(const QByteArray &data, const QByteArray &mask)
{
    if (data.isEmpty()) {
        return data;
    }

    QByteArray out = data;
    for (int i = 0; i < out.size(); ++i) {
        out[i] = static_cast<char>(out.at(i) ^ mask.at(i % mask.size()));
    }
    return out;
}

struct FakeTlsHelloResult
{
    bool valid = false;
    QByteArray clientRandom;
    QByteArray sessionId = QByteArray(32, '\0');
};

struct ObfuscatedHandshakeResult
{
    bool valid = false;
    int dc = 0;
    bool isMedia = false;
    QByteArray protoTag;
    QByteArray clientDecPrekeyIv;
    quint32 protoInt = 0;
};

class AesCtrTransform
{
public:
    ~AesCtrTransform();

    void reset();
    bool init(const QByteArray &key, const QByteArray &iv);
    QByteArray transform(const QByteArray &data);
    bool skip(int size);

private:
    EVP_CIPHER_CTX *m_ctx = nullptr;
};

class TelegramMsgSplitter
{
public:
    TelegramMsgSplitter(const QByteArray &relayInit, quint32 protoInt);

    QList<QByteArray> split(const QByteArray &chunk);
    QList<QByteArray> flush();

private:
    int nextPacketLength() const;
    int nextAbridgedLength() const;
    int nextIntermediateLength() const;

    AesCtrTransform m_decryptor;
    quint32 m_proto = 0;
    QByteArray m_cipherBuffer;
    QByteArray m_plainBuffer;
    bool m_disabled = false;
};

class RawWebSocketClient : public QObject
{
public:
    explicit RawWebSocketClient(QObject *parent = nullptr);

    std::function<void()> onConnected;
    std::function<void(int, const QString &, const QString &, bool)> onHandshakeRejected;
    std::function<void(const QString &)> onError;
    std::function<void(const QByteArray &)> onBinaryMessage;
    std::function<void()> onClosed;

    void connectTo(const QString &targetHost, const QString &domain, int timeoutMs = 10000);
    bool sendBinary(const QByteArray &data);
    bool sendBatch(const QList<QByteArray> &parts);
    void close();

private:
    void processHandshake();
    void processFrames();
    static QByteArray buildFrame(quint8 opcode, const QByteArray &data, bool mask);

    QPointer<QSslSocket> m_socket;
    QTimer m_timeoutTimer;
    QByteArray m_readBuffer;
    QString m_targetHost;
    QString m_domain;
    bool m_connected = false;
};

class TelegramProxySession : public QObject
{
public:
    TelegramProxySession(QTcpSocket *clientSocket, const TelegramProxyRuntimeConfig &config, QObject *parent = nullptr);

private:
    enum class State {
        AwaitingClientHello,
        AwaitingObfuscatedHandshake,
        ConnectingOfficialWs,
        ConnectingCfWs,
        ConnectingTcpFallback,
        BridgingWs,
        BridgingTcp,
        MaskingRelay,
        Closed,
    };

    void onClientReadyRead();
    void processClientInput();
    bool consumeTlsPayloads();
    FakeTlsHelloResult verifyClientHello(const QByteArray &data) const;
    QByteArray buildServerHello(const QByteArray &clientRandom, const QByteArray &sessionId) const;
    bool processObfuscatedHandshake(const QByteArray &handshake);
    ObfuscatedHandshakeResult tryParseObfuscatedHandshake(const QByteArray &handshake) const;
    QByteArray generateRelayInit(const QByteArray &protoTag, qint16 dcIndex) const;
    void startOfficialWs();
    void tryNextOfficialWs();
    void startFallbackChain();
    void tryNextFallbackMethod();
    void tryNextCfProxyDomain();
    void startWebSocket(const QString &targetHost, const QString &domain, std::function<void()> failureHandler);
    void startTcpFallback();
    void flushClientBridgeBuffer();
    void handleRemotePayload(const QByteArray &payload);
    void writeClientPayload(const QByteArray &payload);
    void writeClientRaw(const QByteArray &data);
    void sendRedirectAndClose();
    void startMaskingRelay(const QByteArray &initialData);
    void flushMaskingBuffer();
    QByteArray &clientPayloadBuffer();
    void cleanupWebSocket();
    void cleanupRemoteTcp();
    void cleanupMaskingSocket();
    void closeSession();

    TelegramProxyRuntimeConfig m_config;
    QPointer<QTcpSocket> m_client;
    QPointer<RawWebSocketClient> m_webSocket;
    QPointer<QTcpSocket> m_remoteTcp;
    QPointer<QTcpSocket> m_maskingSocket;

    State m_state = State::AwaitingClientHello;
    bool m_fakeTlsMode = false;

    QByteArray m_secretBytes;
    QByteArray m_clientRawBuffer;
    QByteArray m_clientPayloadBuffer;
    QByteArray m_maskingInitialData;

    AesCtrTransform m_clientDecryptor;
    AesCtrTransform m_clientEncryptor;
    AesCtrTransform m_tgEncryptor;
    AesCtrTransform m_tgDecryptor;

    std::unique_ptr<TelegramMsgSplitter> m_splitter;

    QByteArray m_relayInit;
    int m_dc = 0;
    bool m_isMedia = false;
    quint32 m_protoInt = 0;

    QStringList m_officialDomains;
    int m_officialDomainIndex = 0;

    QStringList m_cfDomains;
    int m_cfDomainIndex = 0;

    QList<FallbackMethod> m_fallbackMethods;
    int m_fallbackIndex = 0;
};

// IMPLEMENTATION_CHUNK_A
AesCtrTransform::~AesCtrTransform()
{
    reset();
}

void AesCtrTransform::reset()
{
    if (m_ctx) {
        EVP_CIPHER_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
}

bool AesCtrTransform::init(const QByteArray &key, const QByteArray &iv)
{
    reset();

    if (key.size() != kKeyLen || iv.size() != kIvLen) {
        return false;
    }

    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx) {
        return false;
    }

    if (EVP_EncryptInit_ex(m_ctx,
                           EVP_aes_256_ctr(),
                           nullptr,
                           reinterpret_cast<const unsigned char *>(key.constData()),
                           reinterpret_cast<const unsigned char *>(iv.constData()))
            != 1) {
        reset();
        return false;
    }

    return true;
}

QByteArray AesCtrTransform::transform(const QByteArray &data)
{
    if (data.isEmpty()) {
        return QByteArray();
    }
    if (!m_ctx) {
        return QByteArray();
    }

    QByteArray out(data.size(), Qt::Uninitialized);
    int outLen = 0;
    if (EVP_EncryptUpdate(m_ctx,
                          reinterpret_cast<unsigned char *>(out.data()),
                          &outLen,
                          reinterpret_cast<const unsigned char *>(data.constData()),
                          data.size())
            != 1) {
        return QByteArray();
    }

    out.truncate(outLen);
    return out;
}

bool AesCtrTransform::skip(const int size)
{
    return !transform(QByteArray(size, '\0')).isNull();
}

TelegramMsgSplitter::TelegramMsgSplitter(const QByteArray &relayInit, const quint32 protoInt)
    : m_proto(protoInt)
{
    if (!m_decryptor.init(relayInit.mid(kSkipLen, kPreKeyLen), relayInit.mid(kSkipLen + kPreKeyLen, kIvLen))) {
        m_disabled = true;
        return;
    }
    m_decryptor.skip(kHandshakeLen);
}

QList<QByteArray> TelegramMsgSplitter::split(const QByteArray &chunk)
{
    if (chunk.isEmpty()) {
        return {};
    }
    if (m_disabled) {
        return { chunk };
    }

    m_cipherBuffer.append(chunk);
    const QByteArray plainChunk = m_decryptor.transform(chunk);
    if (plainChunk.isNull()) {
        m_disabled = true;
        const auto tail = m_cipherBuffer;
        m_cipherBuffer.clear();
        m_plainBuffer.clear();
        return { tail };
    }
    m_plainBuffer.append(plainChunk);

    QList<QByteArray> parts;
    while (!m_cipherBuffer.isEmpty()) {
        const int packetLength = nextPacketLength();
        if (packetLength < 0) {
            break;
        }
        if (packetLength == 0) {
            parts.append(m_cipherBuffer);
            m_cipherBuffer.clear();
            m_plainBuffer.clear();
            m_disabled = true;
            break;
        }

        parts.append(m_cipherBuffer.left(packetLength));
        m_cipherBuffer.remove(0, packetLength);
        m_plainBuffer.remove(0, packetLength);
    }

    return parts;
}

QList<QByteArray> TelegramMsgSplitter::flush()
{
    if (m_cipherBuffer.isEmpty()) {
        return {};
    }

    const QByteArray tail = m_cipherBuffer;
    m_cipherBuffer.clear();
    m_plainBuffer.clear();
    return { tail };
}

int TelegramMsgSplitter::nextPacketLength() const
{
    if (m_plainBuffer.isEmpty()) {
        return -1;
    }
    if (m_proto == kProtoAbridgedInt) {
        return nextAbridgedLength();
    }
    if (m_proto == kProtoIntermediateInt || m_proto == kProtoPaddedIntermediateInt) {
        return nextIntermediateLength();
    }
    return 0;
}

int TelegramMsgSplitter::nextAbridgedLength() const
{
    const auto firstByte = static_cast<quint8>(m_plainBuffer.at(0));
    int payloadLength = 0;
    int headerLength = 0;

    if (firstByte == 0x7F || firstByte == 0xFF) {
        if (m_plainBuffer.size() < 4) {
            return -1;
        }
        payloadLength = (static_cast<quint8>(m_plainBuffer.at(1))
                         | (static_cast<quint8>(m_plainBuffer.at(2)) << 8)
                         | (static_cast<quint8>(m_plainBuffer.at(3)) << 16))
                        * 4;
        headerLength = 4;
    } else {
        payloadLength = (firstByte & 0x7F) * 4;
        headerLength = 1;
    }

    if (payloadLength <= 0) {
        return 0;
    }

    const int packetLength = headerLength + payloadLength;
    return m_plainBuffer.size() < packetLength ? -1 : packetLength;
}

int TelegramMsgSplitter::nextIntermediateLength() const
{
    if (m_plainBuffer.size() < 4) {
        return -1;
    }

    const auto payloadLength = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(m_plainBuffer.constData())) & 0x7FFFFFFF;
    if (payloadLength == 0) {
        return 0;
    }

    const int packetLength = 4 + static_cast<int>(payloadLength);
    return m_plainBuffer.size() < packetLength ? -1 : packetLength;
}

RawWebSocketClient::RawWebSocketClient(QObject *parent)
    : QObject(parent)
{
    m_timeoutTimer.setSingleShot(true);
    connect(&m_timeoutTimer, &QTimer::timeout, this, [this]() {
        if (onError) {
            onError(QStringLiteral("WebSocket timeout"));
        }
        close();
    });
}

void RawWebSocketClient::connectTo(const QString &targetHost, const QString &domain, const int timeoutMs)
{
    close();

    m_targetHost = targetHost;
    m_domain = domain;
    m_connected = false;
    m_readBuffer.clear();

    m_socket = new QSslSocket(this);
    setSocketOptions(m_socket);

    auto sslConfiguration = QSslConfiguration::defaultConfiguration();
    sslConfiguration.setPeerVerifyMode(QSslSocket::VerifyNone);
    m_socket->setPeerVerifyMode(QSslSocket::VerifyNone);
    m_socket->setSslConfiguration(sslConfiguration);

    connect(m_socket, &QTcpSocket::connected, this, [this]() {
        if (!m_socket) {
            return;
        }
        m_socket->setPeerVerifyName(m_domain);
        m_socket->startClientEncryption();
    });

    connect(m_socket, &QSslSocket::encrypted, this, [this]() {
        if (!m_socket) {
            return;
        }

        const QString request =
                QStringLiteral("GET /apiws HTTP/1.1\r\n"
                               "Host: %1\r\n"
                               "Upgrade: websocket\r\n"
                               "Connection: Upgrade\r\n"
                               "Sec-WebSocket-Key: %2\r\n"
                               "Sec-WebSocket-Version: 13\r\n"
                               "Sec-WebSocket-Protocol: binary\r\n"
                               "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\r\n")
                        .arg(m_domain, QString::fromLatin1(randomBytes(16).toBase64()));
        m_socket->write(request.toUtf8());
        m_timeoutTimer.start(10000);
    });

    connect(m_socket, &QIODevice::readyRead, this, [this]() {
        if (!m_socket) {
            return;
        }

        m_readBuffer.append(m_socket->readAll());
        if (!m_connected) {
            processHandshake();
        } else {
            processFrames();
        }
    });

    connect(m_socket, &QSslSocket::sslErrors, this, [this](const QList<QSslError> &) {
        if (m_socket) {
            m_socket->ignoreSslErrors();
        }
    });

    connect(m_socket, &QAbstractSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        if (onError) {
            onError(m_socket ? m_socket->errorString() : QStringLiteral("Socket error"));
        }
        close();
    });

    connect(m_socket, &QAbstractSocket::disconnected, this, [this]() {
        const bool wasConnected = m_connected;
        close();
        if (wasConnected && onClosed) {
            onClosed();
        }
    });

    m_socket->connectToHost(m_targetHost, 443);
    m_timeoutTimer.start(timeoutMs);
}

bool RawWebSocketClient::sendBinary(const QByteArray &data)
{
    if (!m_connected || !m_socket) {
        return false;
    }

    m_socket->write(buildFrame(0x2, data, true));
    return m_socket->waitForBytesWritten(1000);
}

bool RawWebSocketClient::sendBatch(const QList<QByteArray> &parts)
{
    if (!m_connected || !m_socket) {
        return false;
    }

    for (const auto &part : parts) {
        m_socket->write(buildFrame(0x2, part, true));
    }
    return m_socket->waitForBytesWritten(1000);
}

void RawWebSocketClient::close()
{
    m_timeoutTimer.stop();
    m_connected = false;

    if (m_socket) {
        m_socket->disconnect(this);
        m_socket->disconnectFromHost();
        m_socket->deleteLater();
        m_socket = nullptr;
    }

    m_readBuffer.clear();
}

void RawWebSocketClient::processHandshake()
{
    const int headerEnd = m_readBuffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        return;
    }

    m_timeoutTimer.stop();

    const QByteArray headerBytes = m_readBuffer.left(headerEnd);
    m_readBuffer.remove(0, headerEnd + 4);

    const QString headerText = QString::fromUtf8(headerBytes);
    const QStringList lines = headerText.split(QStringLiteral("\r\n"), Qt::SkipEmptyParts);
    if (lines.isEmpty()) {
        if (onError) {
            onError(QStringLiteral("Empty WS handshake response"));
        }
        close();
        return;
    }

    const QString statusLine = lines.first();
    const QStringList statusParts = statusLine.split(QLatin1Char(' '), Qt::SkipEmptyParts);
    const int statusCode = statusParts.size() >= 2 ? statusParts.at(1).toInt() : 0;

    QString location;
    for (int i = 1; i < lines.size(); ++i) {
        const int separator = lines.at(i).indexOf(QLatin1Char(':'));
        if (separator <= 0) {
            continue;
        }
        const QString headerName = lines.at(i).left(separator).trimmed().toLower();
        const QString headerValue = lines.at(i).mid(separator + 1).trimmed();
        if (headerName == QStringLiteral("location")) {
            location = headerValue;
        }
    }

    if (statusCode == 101) {
        m_connected = true;
        if (onConnected) {
            onConnected();
        }
        processFrames();
        return;
    }

    const bool isRedirect = statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308;
    if (onHandshakeRejected) {
        onHandshakeRejected(statusCode, statusLine, location, isRedirect);
    }
    close();
}

void RawWebSocketClient::processFrames()
{
    while (true) {
        if (m_readBuffer.size() < 2) {
            return;
        }

        const quint8 firstByte = static_cast<quint8>(m_readBuffer.at(0));
        const quint8 secondByte = static_cast<quint8>(m_readBuffer.at(1));
        quint64 payloadLength = secondByte & 0x7F;
        int offset = 2;

        if (payloadLength == 126) {
            if (m_readBuffer.size() < offset + 2) {
                return;
            }
            payloadLength = qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(m_readBuffer.constData() + offset));
            offset += 2;
        } else if (payloadLength == 127) {
            if (m_readBuffer.size() < offset + 8) {
                return;
            }
            payloadLength = qFromBigEndian<quint64>(reinterpret_cast<const uchar *>(m_readBuffer.constData() + offset));
            offset += 8;
        }

        QByteArray maskKey;
        if (secondByte & 0x80) {
            if (m_readBuffer.size() < offset + 4) {
                return;
            }
            maskKey = m_readBuffer.mid(offset, 4);
            offset += 4;
        }

        if (m_readBuffer.size() < offset + static_cast<int>(payloadLength)) {
            return;
        }

        QByteArray payload = m_readBuffer.mid(offset, static_cast<int>(payloadLength));
        m_readBuffer.remove(0, offset + static_cast<int>(payloadLength));

        if (!maskKey.isEmpty()) {
            payload = xorMask(payload, maskKey);
        }

        const quint8 opcode = firstByte & 0x0F;
        if (opcode == 0x8) {
            close();
            if (onClosed) {
                onClosed();
            }
            return;
        }
        if (opcode == 0x9) {
            if (m_socket) {
                m_socket->write(buildFrame(0xA, payload, true));
            }
            continue;
        }
        if (opcode == 0xA) {
            continue;
        }
        if ((opcode == 0x1 || opcode == 0x2) && onBinaryMessage) {
            onBinaryMessage(payload);
        }
    }
}

QByteArray RawWebSocketClient::buildFrame(const quint8 opcode, const QByteArray &data, const bool mask)
{
    QByteArray frame;
    frame.append(static_cast<char>(0x80 | opcode));

    const auto appendLength = [&frame, mask](const quint64 length) {
        if (length < 126) {
            frame.append(static_cast<char>((mask ? 0x80 : 0x00) | static_cast<quint8>(length)));
        } else if (length < 65536) {
            frame.append(static_cast<char>((mask ? 0x80 : 0x00) | 126));
            const quint16 value = qToBigEndian<quint16>(static_cast<quint16>(length));
            frame.append(reinterpret_cast<const char *>(&value), sizeof(value));
        } else {
            frame.append(static_cast<char>((mask ? 0x80 : 0x00) | 127));
            const quint64 value = qToBigEndian<quint64>(length);
            frame.append(reinterpret_cast<const char *>(&value), sizeof(value));
        }
    };

    appendLength(static_cast<quint64>(data.size()));

    if (mask) {
        const QByteArray maskKey = randomBytes(4);
        frame.append(maskKey);
        frame.append(xorMask(data, maskKey));
    } else {
        frame.append(data);
    }

    return frame;
}
// IMPLEMENTATION_CHUNK_B
TelegramProxySession::TelegramProxySession(QTcpSocket *clientSocket, const TelegramProxyRuntimeConfig &config, QObject *parent)
    : QObject(parent)
    , m_config(config)
    , m_client(clientSocket)
    , m_secretBytes(QByteArray::fromHex(config.secret.toLatin1()))
{
    m_client->setParent(this);
    setSocketOptions(m_client);

    connect(m_client, &QIODevice::readyRead, this, &TelegramProxySession::onClientReadyRead);
    connect(m_client, &QAbstractSocket::disconnected, this, &TelegramProxySession::closeSession);
}

void TelegramProxySession::onClientReadyRead()
{
    if (m_state == State::Closed || !m_client) {
        return;
    }

    m_clientRawBuffer.append(m_client->readAll());

    if (m_state == State::MaskingRelay) {
        flushMaskingBuffer();
        return;
    }

    processClientInput();
}

void TelegramProxySession::processClientInput()
{
    if (m_state == State::Closed) {
        return;
    }

    if (m_fakeTlsMode && !consumeTlsPayloads()) {
        return;
    }

    while (true) {
        if (m_state == State::AwaitingClientHello) {
            if (!m_config.fakeTlsDomain.isEmpty()) {
                if (m_clientRawBuffer.isEmpty()) {
                    return;
                }

                const auto firstByte = static_cast<quint8>(m_clientRawBuffer.at(0));
                if (firstByte != kTlsRecordHandshake) {
                    sendRedirectAndClose();
                    return;
                }

                if (m_clientRawBuffer.size() < 5) {
                    return;
                }

                const quint16 recordLength = qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(m_clientRawBuffer.constData() + 3));
                if (m_clientRawBuffer.size() < 5 + recordLength) {
                    return;
                }

                const QByteArray clientHello = m_clientRawBuffer.left(5 + recordLength);
                m_clientRawBuffer.remove(0, 5 + recordLength);

                const auto tlsResult = verifyClientHello(clientHello);
                if (!tlsResult.valid) {
                    startMaskingRelay(clientHello);
                    return;
                }

                writeClientRaw(buildServerHello(tlsResult.clientRandom, tlsResult.sessionId));
                m_fakeTlsMode = true;
                m_state = State::AwaitingObfuscatedHandshake;
                if (!consumeTlsPayloads()) {
                    return;
                }
                continue;
            }

            if (m_clientRawBuffer.size() < kHandshakeLen) {
                return;
            }

            const QByteArray handshake = m_clientRawBuffer.left(kHandshakeLen);
            m_clientRawBuffer.remove(0, kHandshakeLen);
            if (!processObfuscatedHandshake(handshake)) {
                closeSession();
                return;
            }
            continue;
        }

        if (m_state == State::AwaitingObfuscatedHandshake) {
            if (m_clientPayloadBuffer.size() < kHandshakeLen) {
                return;
            }

            const QByteArray handshake = m_clientPayloadBuffer.left(kHandshakeLen);
            m_clientPayloadBuffer.remove(0, kHandshakeLen);
            if (!processObfuscatedHandshake(handshake)) {
                closeSession();
                return;
            }
            continue;
        }

        if (m_state == State::BridgingWs || m_state == State::BridgingTcp) {
            flushClientBridgeBuffer();
        }
        return;
    }
}

bool TelegramProxySession::consumeTlsPayloads()
{
    while (m_clientRawBuffer.size() >= 5) {
        const quint8 recordType = static_cast<quint8>(m_clientRawBuffer.at(0));
        const quint16 recordLength = qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(m_clientRawBuffer.constData() + 3));
        if (m_clientRawBuffer.size() < 5 + recordLength) {
            return true;
        }

        const QByteArray payload = m_clientRawBuffer.mid(5, recordLength);
        m_clientRawBuffer.remove(0, 5 + recordLength);

        if (recordType == kTlsRecordChangeCipherSpec) {
            continue;
        }

        if (recordType != kTlsRecordApplicationData) {
            closeSession();
            return false;
        }

        m_clientPayloadBuffer.append(payload);
    }

    return true;
}

FakeTlsHelloResult TelegramProxySession::verifyClientHello(const QByteArray &data) const
{
    FakeTlsHelloResult result;
    if (data.size() < 43 || static_cast<quint8>(data.at(0)) != kTlsRecordHandshake || static_cast<quint8>(data.at(5)) != 0x01) {
        return result;
    }

    const QByteArray clientRandom = data.mid(11, 32);
    QByteArray zeroed = data;
    zeroed.replace(11, 32, QByteArray(32, '\0'));

    const QByteArray expected = hmacSha256(m_secretBytes, zeroed);
    if (expected.size() < 32 || clientRandom.left(28) != expected.left(28)) {
        return result;
    }

    QByteArray timestampBytes(4, '\0');
    for (int i = 0; i < 4; ++i) {
        timestampBytes[i] = static_cast<char>(clientRandom.at(28 + i) ^ expected.at(28 + i));
    }

    const quint32 timestamp = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(timestampBytes.constData()));
    const auto now = static_cast<quint32>(QDateTime::currentSecsSinceEpoch());
    if ((now > timestamp && now - timestamp > kTimestampToleranceSeconds)
        || (timestamp > now && timestamp - now > kTimestampToleranceSeconds)) {
        return result;
    }

    result.valid = true;
    result.clientRandom = clientRandom;
    if (data.size() >= 76 && static_cast<quint8>(data.at(43)) == 0x20) {
        result.sessionId = data.mid(44, 32);
    }
    return result;
}

QByteArray TelegramProxySession::buildServerHello(const QByteArray &clientRandom, const QByteArray &sessionId) const
{
    QByteArray response = buildServerHelloTemplate();
    response.replace(44, 32, sessionId);
    response.replace(89, 32, randomBytes(32));

    const QByteArray ccs(QByteArray::fromHex("140303000101"));
    const int encryptedSize = QRandomGenerator::system()->bounded(1900, 2101);
    const QByteArray appData = randomBytes(encryptedSize);

    QByteArray appRecord;
    appRecord.append(char(kTlsRecordApplicationData));
    appRecord.append(QByteArray::fromHex("0303"));
    const quint16 beLength = qToBigEndian<quint16>(static_cast<quint16>(encryptedSize));
    appRecord.append(reinterpret_cast<const char *>(&beLength), sizeof(beLength));
    appRecord.append(appData);

    QByteArray finalResponse = response + ccs + appRecord;
    finalResponse.replace(11, 32, hmacSha256(m_secretBytes, clientRandom + finalResponse).left(32));
    return finalResponse;
}

bool TelegramProxySession::processObfuscatedHandshake(const QByteArray &handshake)
{
    const auto result = tryParseObfuscatedHandshake(handshake);
    if (!result.valid) {
        return false;
    }

    m_dc = result.dc;
    m_isMedia = result.isMedia;
    m_protoInt = result.protoInt;
    m_relayInit = generateRelayInit(result.protoTag, m_isMedia ? -m_dc : m_dc);

    const QByteArray clientDecPreKey = result.clientDecPrekeyIv.left(kPreKeyLen);
    const QByteArray clientDecIv = result.clientDecPrekeyIv.mid(kPreKeyLen, kIvLen);
    const QByteArray clientDecKey = sha256(clientDecPreKey + m_secretBytes);

    const QByteArray clientEncPreKeyIv = reverseByteArray(result.clientDecPrekeyIv);
    const QByteArray clientEncKey = sha256(clientEncPreKeyIv.left(kPreKeyLen) + m_secretBytes);
    const QByteArray clientEncIv = clientEncPreKeyIv.mid(kPreKeyLen, kIvLen);

    if (!m_clientDecryptor.init(clientDecKey, clientDecIv) || !m_clientEncryptor.init(clientEncKey, clientEncIv)) {
        return false;
    }
    m_clientDecryptor.skip(kHandshakeLen);

    const QByteArray relayEncKey = m_relayInit.mid(kSkipLen, kPreKeyLen);
    const QByteArray relayEncIv = m_relayInit.mid(kSkipLen + kPreKeyLen, kIvLen);
    const QByteArray relayDecPreKeyIv = reverseByteArray(m_relayInit.mid(kSkipLen, kPreKeyLen + kIvLen));
    const QByteArray relayDecKey = relayDecPreKeyIv.left(kKeyLen);
    const QByteArray relayDecIv = relayDecPreKeyIv.mid(kKeyLen, kIvLen);

    if (!m_tgEncryptor.init(relayEncKey, relayEncIv) || !m_tgDecryptor.init(relayDecKey, relayDecIv)) {
        return false;
    }
    m_tgEncryptor.skip(kHandshakeLen);

    m_splitter = std::make_unique<TelegramMsgSplitter>(m_relayInit, m_protoInt);
    startOfficialWs();
    return true;
}

ObfuscatedHandshakeResult TelegramProxySession::tryParseObfuscatedHandshake(const QByteArray &handshake) const
{
    ObfuscatedHandshakeResult result;
    if (handshake.size() < kHandshakeLen) {
        return result;
    }

    const QByteArray clientDecPrekeyIv = handshake.mid(kSkipLen, kPreKeyLen + kIvLen);
    const QByteArray clientDecKey = sha256(clientDecPrekeyIv.left(kPreKeyLen) + m_secretBytes);
    const QByteArray clientDecIv = clientDecPrekeyIv.mid(kPreKeyLen, kIvLen);

    AesCtrTransform decryptor;
    if (!decryptor.init(clientDecKey, clientDecIv)) {
        return result;
    }

    const QByteArray decrypted = decryptor.transform(handshake);
    if (decrypted.size() < kHandshakeLen) {
        return result;
    }

    const QByteArray protoTag = decrypted.mid(kProtoTagPos, 4);
    quint32 protoInt = 0;
    if (protoTag == kProtoTagAbridged) {
        protoInt = kProtoAbridgedInt;
    } else if (protoTag == kProtoTagIntermediate) {
        protoInt = kProtoIntermediateInt;
    } else if (protoTag == kProtoTagSecure) {
        protoInt = kProtoPaddedIntermediateInt;
    } else {
        return result;
    }

    const qint16 dcIndex = qFromLittleEndian<qint16>(reinterpret_cast<const uchar *>(decrypted.constData() + kDcIdxPos));
    result.valid = true;
    result.dc = std::abs(static_cast<int>(dcIndex));
    result.isMedia = dcIndex < 0;
    result.protoTag = protoTag;
    result.clientDecPrekeyIv = clientDecPrekeyIv;
    result.protoInt = protoInt;
    return result;
}

QByteArray TelegramProxySession::generateRelayInit(const QByteArray &protoTag, const qint16 dcIndex) const
{
    QByteArray randomHandshake;
    while (true) {
        randomHandshake = randomBytes(kHandshakeLen);
        const auto firstByte = static_cast<quint8>(randomHandshake.at(0));
        if (firstByte == 0xEF) {
            continue;
        }
        if (kReservedStarts.contains(randomHandshake.left(4))) {
            continue;
        }
        if (randomHandshake.mid(4, 4) == kReservedContinue) {
            continue;
        }
        break;
    }

    const QByteArray encKey = randomHandshake.mid(kSkipLen, kPreKeyLen);
    const QByteArray encIv = randomHandshake.mid(kSkipLen + kPreKeyLen, kIvLen);

    AesCtrTransform encryptor;
    if (!encryptor.init(encKey, encIv)) {
        return randomHandshake;
    }

    const QByteArray encryptedFull = encryptor.transform(randomHandshake);
    const QByteArray keyStreamTail = xorMask(encryptedFull.mid(56, 8), randomHandshake.mid(56, 8));

    QByteArray tailPlain = protoTag;
    const qint16 littleDc = qToLittleEndian<qint16>(dcIndex);
    tailPlain.append(reinterpret_cast<const char *>(&littleDc), sizeof(littleDc));
    tailPlain.append(randomBytes(2));

    QByteArray encryptedTail(8, '\0');
    for (int i = 0; i < 8; ++i) {
        encryptedTail[i] = static_cast<char>(tailPlain.at(i) ^ keyStreamTail.at(i));
    }

    randomHandshake.replace(kProtoTagPos, 8, encryptedTail);
    return randomHandshake;
}

void TelegramProxySession::startOfficialWs()
{
    m_officialDomains = wsDomains(m_dc, m_isMedia);
    m_officialDomainIndex = 0;
    tryNextOfficialWs();
}

void TelegramProxySession::tryNextOfficialWs()
{
    const QString targetIp = kDefaultWsTargetIps.value(m_dc);
    if (targetIp.isEmpty() || m_officialDomainIndex >= m_officialDomains.size()) {
        startFallbackChain();
        return;
    }

    const QString domain = m_officialDomains.at(m_officialDomainIndex++);
    m_state = State::ConnectingOfficialWs;
    startWebSocket(targetIp, domain, [this]() { tryNextOfficialWs(); });
}

void TelegramProxySession::startFallbackChain()
{
    m_fallbackMethods.clear();
    if (m_config.cfProxyEnabled && m_config.cfProxyPriorityEnabled) {
        m_fallbackMethods.append(FallbackMethod::CfProxy);
        m_fallbackMethods.append(FallbackMethod::Tcp);
    } else if (m_config.cfProxyEnabled) {
        m_fallbackMethods.append(FallbackMethod::Tcp);
        m_fallbackMethods.append(FallbackMethod::CfProxy);
    } else {
        m_fallbackMethods.append(FallbackMethod::Tcp);
    }

    m_fallbackIndex = 0;
    tryNextFallbackMethod();
}

void TelegramProxySession::tryNextFallbackMethod()
{
    if (m_fallbackIndex >= m_fallbackMethods.size()) {
        closeSession();
        return;
    }

    const auto method = m_fallbackMethods.at(m_fallbackIndex++);
    if (method == FallbackMethod::CfProxy) {
        m_cfDomains = m_config.cfProxyDomain.isEmpty() ? kDefaultCfProxyDomains : QStringList { m_config.cfProxyDomain };
        m_cfDomainIndex = 0;
        tryNextCfProxyDomain();
        return;
    }

    startTcpFallback();
}

void TelegramProxySession::tryNextCfProxyDomain()
{
    if (m_cfDomainIndex >= m_cfDomains.size()) {
        tryNextFallbackMethod();
        return;
    }

    const QString domain = QStringLiteral("kws%1.%2").arg(m_dc).arg(m_cfDomains.at(m_cfDomainIndex++));
    m_state = State::ConnectingCfWs;
    startWebSocket(domain, domain, [this]() { tryNextCfProxyDomain(); });
}
// IMPLEMENTATION_CHUNK_C
void TelegramProxySession::startWebSocket(const QString &targetHost, const QString &domain, std::function<void()> failureHandler)
{
    cleanupWebSocket();

    auto *socket = new RawWebSocketClient(this);
    m_webSocket = socket;

    socket->onConnected = [this, socket, failureHandler]() {
        if (m_state == State::Closed || m_webSocket != socket) {
            return;
        }

        if (!socket->sendBinary(m_relayInit)) {
            cleanupWebSocket();
            failureHandler();
            return;
        }

        m_state = State::BridgingWs;
        flushClientBridgeBuffer();
    };

    socket->onHandshakeRejected = [this, socket, failureHandler](int, const QString &, const QString &, bool) {
        if (m_state == State::Closed || m_webSocket != socket) {
            return;
        }
        cleanupWebSocket();
        failureHandler();
    };

    socket->onError = [this, socket, failureHandler](const QString &) {
        if (m_state == State::Closed || m_webSocket != socket) {
            return;
        }
        cleanupWebSocket();
        failureHandler();
    };

    socket->onBinaryMessage = [this, socket](const QByteArray &data) {
        if (m_state == State::Closed || m_webSocket != socket) {
            return;
        }
        handleRemotePayload(data);
    };

    socket->onClosed = [this, socket]() {
        if (m_state == State::Closed || m_webSocket != socket) {
            return;
        }
        closeSession();
    };

    socket->connectTo(targetHost, domain);
}

void TelegramProxySession::startTcpFallback()
{
    const QString ip = fallbackTcpIp(m_dc);
    if (ip.isEmpty()) {
        tryNextFallbackMethod();
        return;
    }

    cleanupRemoteTcp();
    m_state = State::ConnectingTcpFallback;
    m_remoteTcp = new QTcpSocket(this);
    setSocketOptions(m_remoteTcp);

    connect(m_remoteTcp, &QTcpSocket::connected, this, [this]() {
        if (!m_remoteTcp || m_state == State::Closed) {
            return;
        }
        m_remoteTcp->write(m_relayInit);
        m_state = State::BridgingTcp;
        flushClientBridgeBuffer();
    });

    connect(m_remoteTcp, &QIODevice::readyRead, this, [this]() {
        if (!m_remoteTcp || m_state != State::BridgingTcp) {
            return;
        }
        handleRemotePayload(m_remoteTcp->readAll());
    });

    connect(m_remoteTcp, &QAbstractSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        if (m_state == State::ConnectingTcpFallback) {
            cleanupRemoteTcp();
            tryNextFallbackMethod();
            return;
        }
        closeSession();
    });

    connect(m_remoteTcp, &QAbstractSocket::disconnected, this, [this]() {
        if (m_state == State::ConnectingTcpFallback) {
            cleanupRemoteTcp();
            tryNextFallbackMethod();
            return;
        }
        closeSession();
    });

    m_remoteTcp->connectToHost(ip, 443);
}

void TelegramProxySession::flushClientBridgeBuffer()
{
    QByteArray &buffer = clientPayloadBuffer();
    if (buffer.isEmpty()) {
        return;
    }

    const QByteArray encryptedFromClient = std::exchange(buffer, QByteArray());
    const QByteArray plain = m_clientDecryptor.transform(encryptedFromClient);
    if (plain.isNull()) {
        closeSession();
        return;
    }

    const QByteArray encryptedToTelegram = m_tgEncryptor.transform(plain);
    if (encryptedToTelegram.isNull()) {
        closeSession();
        return;
    }

    if (m_state == State::BridgingWs && m_webSocket) {
        const QList<QByteArray> parts = m_splitter ? m_splitter->split(encryptedToTelegram) : QList<QByteArray> { encryptedToTelegram };
        if (parts.size() > 1) {
            if (!m_webSocket->sendBatch(parts)) {
                closeSession();
            }
        } else if (!parts.isEmpty()) {
            if (!m_webSocket->sendBinary(parts.constFirst())) {
                closeSession();
            }
        }
        return;
    }

    if (m_state == State::BridgingTcp && m_remoteTcp) {
        m_remoteTcp->write(encryptedToTelegram);
        return;
    }

    buffer = encryptedFromClient + buffer;
}

void TelegramProxySession::handleRemotePayload(const QByteArray &payload)
{
    if (m_state == State::Closed || payload.isEmpty()) {
        return;
    }

    const QByteArray plain = m_tgDecryptor.transform(payload);
    if (plain.isNull()) {
        closeSession();
        return;
    }

    const QByteArray encryptedToClient = m_clientEncryptor.transform(plain);
    if (encryptedToClient.isNull()) {
        closeSession();
        return;
    }

    writeClientPayload(encryptedToClient);
}

void TelegramProxySession::writeClientPayload(const QByteArray &payload)
{
    if (!m_client) {
        return;
    }

    if (!m_fakeTlsMode) {
        writeClientRaw(payload);
        return;
    }

    int offset = 0;
    while (offset < payload.size()) {
        const QByteArray chunk = payload.mid(offset, kTlsAppDataMax);
        QByteArray record;
        record.append(char(kTlsRecordApplicationData));
        record.append(QByteArray::fromHex("0303"));
        const quint16 beLength = qToBigEndian<quint16>(static_cast<quint16>(chunk.size()));
        record.append(reinterpret_cast<const char *>(&beLength), sizeof(beLength));
        record.append(chunk);
        writeClientRaw(record);
        offset += chunk.size();
    }
}

void TelegramProxySession::writeClientRaw(const QByteArray &data)
{
    if (m_client) {
        m_client->write(data);
    }
}

void TelegramProxySession::sendRedirectAndClose()
{
    if (!m_client) {
        deleteLater();
        return;
    }

    const QByteArray redirect =
            QStringLiteral("HTTP/1.1 301 Moved Permanently\r\n"
                           "Location: https://%1/\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n")
                    .arg(m_config.fakeTlsDomain)
                    .toUtf8();
    m_client->write(redirect);
    closeSession();
}

void TelegramProxySession::startMaskingRelay(const QByteArray &initialData)
{
    if (m_config.fakeTlsDomain.isEmpty()) {
        closeSession();
        return;
    }

    cleanupMaskingSocket();
    m_state = State::MaskingRelay;
    m_maskingInitialData = initialData;
    m_maskingSocket = new QTcpSocket(this);
    setSocketOptions(m_maskingSocket);

    connect(m_maskingSocket, &QTcpSocket::connected, this, [this]() {
        flushMaskingBuffer();
    });

    connect(m_maskingSocket, &QIODevice::readyRead, this, [this]() {
        if (!m_maskingSocket || !m_client) {
            return;
        }
        m_client->write(m_maskingSocket->readAll());
    });

    connect(m_maskingSocket, &QAbstractSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        closeSession();
    });

    connect(m_maskingSocket, &QAbstractSocket::disconnected, this, [this]() {
        closeSession();
    });

    m_maskingSocket->connectToHost(m_config.fakeTlsDomain, 443);
}

void TelegramProxySession::flushMaskingBuffer()
{
    if (!m_maskingSocket || m_maskingSocket->state() != QAbstractSocket::ConnectedState) {
        return;
    }

    if (!m_maskingInitialData.isEmpty()) {
        m_maskingSocket->write(m_maskingInitialData);
        m_maskingInitialData.clear();
    }

    if (!m_clientRawBuffer.isEmpty()) {
        m_maskingSocket->write(m_clientRawBuffer);
        m_clientRawBuffer.clear();
    }
}

QByteArray &TelegramProxySession::clientPayloadBuffer()
{
    return m_fakeTlsMode ? m_clientPayloadBuffer : m_clientRawBuffer;
}

void TelegramProxySession::cleanupWebSocket()
{
    if (m_webSocket) {
        m_webSocket->close();
        m_webSocket->deleteLater();
        m_webSocket = nullptr;
    }
}

void TelegramProxySession::cleanupRemoteTcp()
{
    if (m_remoteTcp) {
        m_remoteTcp->disconnect(this);
        m_remoteTcp->disconnectFromHost();
        m_remoteTcp->deleteLater();
        m_remoteTcp = nullptr;
    }
}

void TelegramProxySession::cleanupMaskingSocket()
{
    if (m_maskingSocket) {
        m_maskingSocket->disconnect(this);
        m_maskingSocket->disconnectFromHost();
        m_maskingSocket->deleteLater();
        m_maskingSocket = nullptr;
    }
}

void TelegramProxySession::closeSession()
{
    if (m_state == State::Closed) {
        deleteLater();
        return;
    }

    m_state = State::Closed;

    if (m_splitter && m_webSocket) {
        const auto tail = m_splitter->flush();
        if (!tail.isEmpty()) {
            m_webSocket->sendBatch(tail);
        }
    }

    cleanupWebSocket();
    cleanupRemoteTcp();
    cleanupMaskingSocket();

    if (m_client) {
        m_client->disconnect(this);
        m_client->disconnectFromHost();
        m_client->deleteLater();
        m_client = nullptr;
    }

    deleteLater();
}
} // namespace

TelegramWsProxyEngine::TelegramWsProxyEngine(QObject *parent)
    : QObject(parent)
{
}

void TelegramWsProxyEngine::start(const TelegramProxyRuntimeConfig &config)
{
    stop();

    if (config.port == 0 || config.secret.size() != 32) {
        emit errorOccurred(tr("Invalid Telegram proxy configuration"));
        return;
    }

    m_config = config;

    if (!m_server) {
        m_server = new QTcpServer(this);
        connect(m_server, &QTcpServer::newConnection, this, &TelegramWsProxyEngine::onNewConnection);
    }

    QHostAddress listenAddress = QHostAddress::LocalHost;
    if (config.listenHost == QLatin1String("0.0.0.0")) {
        listenAddress = QHostAddress::AnyIPv4;
    } else {
        QHostAddress parsedAddress;
        if (parsedAddress.setAddress(config.listenHost)) {
            listenAddress = parsedAddress;
        } else if (!config.listenHost.compare(QStringLiteral("localhost"), Qt::CaseInsensitive)) {
            listenAddress = QHostAddress::LocalHost;
        }
    }

    if (!m_server->listen(listenAddress, config.port)) {
        emit errorOccurred(tr("Failed to start Telegram WS proxy on %1:%2: %3")
                                   .arg(config.listenHost)
                                   .arg(config.port)
                                   .arg(m_server->errorString()));
        return;
    }

    m_running = true;
    emit statusTextChanged(tr("Running on %1:%2").arg(config.listenHost).arg(config.port));
    emit message(tr("Telegram WS proxy is listening on %1:%2").arg(config.listenHost).arg(config.port));
    emit started();
}

void TelegramWsProxyEngine::stop()
{
    if (m_server) {
        m_server->close();
    }

    const auto sessions = m_sessions;
    for (QObject *session : sessions) {
        if (session) {
            session->deleteLater();
        }
    }
    m_sessions.clear();

    if (m_running) {
        m_running = false;
    }

    emit statusTextChanged(tr("Stopped"));
    emit stopped();
}

void TelegramWsProxyEngine::onNewConnection()
{
    if (!m_server) {
        return;
    }

    while (m_server->hasPendingConnections()) {
        QTcpSocket *clientSocket = m_server->nextPendingConnection();
        if (!clientSocket) {
            continue;
        }

        auto *session = new TelegramProxySession(clientSocket, m_config, this);
        m_sessions.insert(session);
        connect(session, &QObject::destroyed, this, [this, session]() {
            m_sessions.remove(session);
        });
    }
}
