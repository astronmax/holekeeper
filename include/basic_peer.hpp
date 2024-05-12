#pragma once

#include <common.hpp>

#include <QtNetwork/QUdpSocket>

class BasicPeer final : public Peer {
    Q_OBJECT

public:
    explicit BasicPeer(ConfigManager&);
    ~BasicPeer() = default;

    void send_data(QByteArray const&, HostAddress) override;
    void register_peer(PeerInfo) override;
    void ping_active_peers() override;

public slots:
    void read_data();

private:
    void make_holepunch(HostAddress, bool brute_enable = false);

private:
    std::shared_ptr<QUdpSocket> _socket;
};
