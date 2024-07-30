#pragma once

#include "common.hpp"

#include <QtCore/QObject>
#include <QtCore/QTimer>
#include <QtNetwork/QUdpSocket>

#include <memory>

namespace hk {

struct ChannelInfo {
    std::string nickname;
    HostAddress address;
    bool holepunching;

    auto to_base64() -> QByteArray;
    static auto from_base64(QByteArray const&) -> ChannelInfo;
};

class AbstractChannel : public QObject {
    Q_OBJECT

public:
    virtual auto connect_peer(std::shared_ptr<ChannelInfo>) -> void { }

    auto send(QByteArray const&) -> void;
    auto send_ping() -> void;
    auto get_self_info() -> std::shared_ptr<ChannelInfo>;
    auto get_peer_info() -> std::shared_ptr<ChannelInfo>;

protected:
    virtual auto send_data(QByteArray&) -> void { }
    auto process_data(QByteArray const&) -> void;

private:
    auto send_pong() -> void;
    auto start_ping_timer() -> void;
    auto stop_ping_timer() -> void;

signals:
    auto channel_ready() -> void;
    auto peer_connected() -> void;
    auto data_received(std::string, QByteArray const&) -> void;

protected:
    std::shared_ptr<QUdpSocket> m_socket;
    std::shared_ptr<ChannelInfo> m_self_info;
    std::shared_ptr<ChannelInfo> m_peer_info;

private:
    std::unique_ptr<QTimer> m_ping_timer;
    std::size_t m_ping_attempts = 5;
    bool m_peer_connected;
};

};
