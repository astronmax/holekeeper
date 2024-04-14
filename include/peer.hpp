#pragma once

#include <common.hpp>
#include <stun.hpp>
#include <turn.hpp>

#include <QtNetwork/QUdpSocket>

struct PeerInfoType final {
    std::string nickname;
    HostAddress address;
};

using PeerInfo = std::shared_ptr<PeerInfoType>;

QByteArray pack_peer_info(PeerInfo);
PeerInfo unpack_peer_info(QByteArray);
