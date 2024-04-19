#pragma once

#include <common.hpp>

struct PeerInfo final {
    std::string nickname;
    HostAddress address;
};

struct SignalClient final {
public:
    explicit SignalClient(HostAddress);
    void add_peer_info(PeerInfo);
    void find_online_peers();
    std::vector<PeerInfo>& get_online_peers();

private:
    HostAddress _signal_server;
    std::shared_ptr<QUdpSocket> _socket;
    std::vector<PeerInfo> _peers_online;
};
