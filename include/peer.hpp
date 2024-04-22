#pragma once

#include <common.hpp>

#include <QtNetwork/QUdpSocket>

#include <queue>

struct PeerInfo {
    std::string nickname;
    HostAddress address;
    NatType nat_type;
};
