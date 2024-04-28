#pragma once

#include <common.hpp>

#include <QtNetwork/QUdpSocket>

class TurnPeer final : public Peer {
    Q_OBJECT

public:
    explicit TurnPeer(ConfigManager&);
    ~TurnPeer();

    void send_data(QByteArray const&, HostAddress) override;
    void register_peer(PeerInfo) override;
    void ping_active_peers() override;

public slots:
    void read_data();

private:
    void send_to_server(QByteArray const&);
    void refresh(uint32_t);
    HostAddress allocate_address();

private:
    QByteArray _nonce;
    QByteArray _integrity_key;
    TurnSettings _server;
    std::shared_ptr<QUdpSocket> _socket;
};

class ServerError : public std::runtime_error {
public:
    ServerError(const std::string&);
    virtual ~ServerError() noexcept = default;
};
