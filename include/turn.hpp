#pragma once

#include <stun.hpp>

#include <QtNetwork/QHostAddress>
#include <QtNetwork/QUdpSocket>

#include <memory>
#include <utility>

namespace turn {

struct Client {
public:
    Client(QHostAddress, uint16_t, std::string, std::string);
    ~Client();

public:
    std::pair<QHostAddress, uint16_t> allocate_address();
    void create_permission(std::string, uint16_t);
    void refresh(uint32_t);

    void send_data(QByteArray, std::string, uint16_t);
    QByteArray recv_data();

private:
    constexpr static size_t BUFFER_SIZE = 2048;
    std::string _username;
    std::shared_ptr<QUdpSocket> _socket;
    std::pair<QHostAddress, uint16_t> _server_addr;
    QByteArray _integrity_key;
    QByteArray _nonce;
};

};
