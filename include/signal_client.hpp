#pragma once

#include <common.hpp>
#include <peer.hpp>

#include <QtNetwork/QUdpSocket>

class SignalClient final {
public:
    explicit SignalClient(HostAddress);
    void add_peer_info(std::shared_ptr<PeerInfo>);
    void find_online_peers();
    std::vector<std::shared_ptr<PeerInfo>>& get_online_peers();
    HostAddress get_server_addr() const;

private:
    HostAddress _signal_server;
    std::shared_ptr<QUdpSocket> _socket;
    std::vector<std::shared_ptr<PeerInfo>> _peers_online;
};
