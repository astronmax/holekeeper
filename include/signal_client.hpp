#pragma once

#include <common.hpp>

#include <QtNetwork/QUdpSocket>

class SignalClient final {
public:
    explicit SignalClient(HostAddress);
    void add_peer_info(PeerInfo);
    void find_online_peers();
    std::vector<PeerInfo>& get_online_peers();
    HostAddress get_server_addr() const;

private:
    HostAddress _signal_server;
    std::shared_ptr<QUdpSocket> _socket;
    std::vector<PeerInfo> _peers_online;
};
