#pragma once

#include <common.hpp>

#include <QtNetwork/QUdpSocket>

#include <queue>

struct PeerInfo {
    std::string nickname;
    HostAddress address;
    NatType nat_type;
};

class CommonPeer final : public QObject {
    Q_OBJECT

public:
    explicit CommonPeer(std::shared_ptr<ConfigManager>);
    ~CommonPeer() = default;

    void send_data(QByteArray const&, HostAddress);
    void make_holepunch(HostAddress, bool brute_enable = false);
    std::shared_ptr<PeerInfo> get_info();
    void ping_active_peers();
    QSet<HostAddress>& get_active_peers();

signals:
    void data_received(QByteArray, HostAddress);
    void holepunch_success(HostAddress);

public slots:
    void read_data();

private:
    std::shared_ptr<PeerInfo> _peer_info;
    std::shared_ptr<QUdpSocket> _socket;
    QSet<HostAddress> _active_peers;
};
