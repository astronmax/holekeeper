#pragma once

#include <QtCore/QtCore>

#include <type_traits>
#include <vector>

using HostAddress = std::pair<std::string, uint16_t>;

enum class NatType {
    COMMON,
    SYMMETRIC,
};

struct TurnSettings {
    HostAddress address;
    std::string username;
    std::string password;
};

struct PeerInfo {
    std::string nickname;
    HostAddress address;
    NatType nat_type;
};

class ConfigManager final {
public:
    explicit ConfigManager(QString const& filename)
    {
        QFile config_file;
        config_file.setFileName(filename);
        config_file.open(QIODevice::ReadOnly | QIODevice::Text);
        const auto json_val = config_file.readAll();
        _config_object = QJsonDocument::fromJson(json_val).object();
    }

    std::string get_nickname() { return _config_object.value("nickname").toString().toStdString(); }

    uint16_t get_port() { return _config_object.value("port").toInt(); }

    bool turn_using() { return _config_object.value("turn_using").toBool(); }

    HostAddress get_signal_server()
    {
        const auto obj = _config_object.value("signal_server").toObject();
        const auto ip = obj.value("host").toString().toStdString();
        const auto port = obj.value("port").toInt();
        return std::make_pair(ip, port);
    }

    TurnSettings get_turn_server()
    {
        const auto obj = _config_object.value("turn_server").toObject();
        const auto ip = obj.value("host").toString().toStdString();
        const auto port = obj.value("port").toInt();
        const auto username = obj.value("username").toString().toStdString();
        const auto password = obj.value("password").toString().toStdString();

        return TurnSettings { { ip, port }, username, password };
    }

    std::vector<HostAddress> get_stun_servers()
    {
        std::vector<HostAddress> stun_servers;
        auto stun_array = _config_object.value("stun_servers").toArray();
        for (const auto& stun_val : stun_array) {
            auto obj = stun_val.toObject();
            auto ip = obj.value("host").toString().toStdString();
            auto port = obj.value("port").toInt();
            stun_servers.push_back({ ip, port });
        }

        return stun_servers;
    }

private:
    QJsonObject _config_object;
};

template <typename T>
QByteArray int_to_bytes(const T integer)
{
    if (!std::is_integral_v<T>) {
        throw std::invalid_argument { "Needs integral type" };
    }

    QByteArray result {};
    for (size_t i = 0; i < sizeof(T); i++) {
        result.push_back((integer >> (8 * (sizeof(T) - i - 1))) & 0xFF);
    }

    return result;
}

template <typename T>
auto bytes_to_int(const QByteArray bytes) -> T
{
    if (!std::is_integral_v<T>) {
        throw std::invalid_argument { "Needs integral type" };
    }

    T result {};
    for (auto byte : bytes) {
        result = (result << 8) | static_cast<uint8_t>(byte);
    }

    return result;
}
