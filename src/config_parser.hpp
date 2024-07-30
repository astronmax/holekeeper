#pragma once

#include "common.hpp"

#include <QtCore/QJsonObject>
#include <QtCore/QString>

namespace hk {

struct TurnSettings {
    HostAddress address;
    std::string username;
    std::string password;
};

class ConfigParser final {
public:
    explicit ConfigParser(QString const&);

    auto nickname() -> std::string;
    auto port() -> std::uint16_t;
    auto turn_using() -> bool;
    auto turn_server() -> TurnSettings;
    auto stun_servers() -> std::vector<HostAddress>;

private:
    QJsonObject m_config_object;
};

};
