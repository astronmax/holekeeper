#pragma once

#include "abstract_channel.hpp"
#include "common.hpp"
#include "config_parser.hpp"

#include <QtCore/QTimer>

namespace hk {

class TurnChannel final : public AbstractChannel {
public:
    explicit TurnChannel(ConfigParser&);
    ~TurnChannel();

public:
    auto connect_peer(std::shared_ptr<ChannelInfo>) -> void;

private slots:
    auto process() -> void;
    auto start_refreshing() -> void;

private:
    auto send_data(QByteArray&) -> void;
    auto send_allocation_request() -> void;
    auto send_refresh_request(std::uint32_t) -> void;

private:
    TurnSettings m_turn_settings;
    QByteArray m_integrity_key;
    QByteArray m_nonce;
    QTimer m_refresh_timer;
    QTimer m_receive_timer;
};

};
