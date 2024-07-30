#include "config_parser.hpp"
#include "common.hpp"

#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>

using namespace hk;

ConfigParser::ConfigParser(QString const& filename) {
    QFile config_file;
    config_file.setFileName(filename);
    config_file.open(QIODevice::ReadOnly | QIODevice::Text);
    const auto json_val = config_file.readAll();
    m_config_object = QJsonDocument::fromJson(json_val).object();
}

auto ConfigParser::nickname() -> std::string { return m_config_object.value("nickname").toString().toStdString(); }
auto ConfigParser::port() -> std::uint16_t { return m_config_object.value("port").toInt(); }
auto ConfigParser::turn_using() -> bool { return m_config_object.value("turn_using").toBool(); }

auto ConfigParser::turn_server() -> TurnSettings {
    const auto obj = m_config_object.value("turn_server").toObject();
    const auto ip = obj.value("host").toString().toStdString();
    const auto port = obj.value("port").toInt();
    const auto username = obj.value("username").toString().toStdString();
    const auto password = obj.value("password").toString().toStdString();

    return TurnSettings { { ip, port }, username, password };
}

auto ConfigParser::stun_servers() -> std::vector<HostAddress> {
    std::vector<HostAddress> stun_servers;
    auto stun_array = m_config_object.value("stun_servers").toArray();
    for (const auto& stun_val : stun_array) {
        auto obj = stun_val.toObject();
        auto ip = obj.value("host").toString().toStdString();
        auto port = obj.value("port").toInt();
        stun_servers.push_back({ ip, port });
    }

    return stun_servers;
}
