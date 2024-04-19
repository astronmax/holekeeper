#pragma once

#include <common.hpp>
#include <stun.hpp>

#include <QtNetwork/QUdpSocket>

#include <memory>
#include <utility>

namespace turn {

class Client {
public:
    explicit Client(HostAddress, std::string, std::string);
    ~Client();

public:
    HostAddress allocate_address();
    void create_permission(HostAddress);
    void refresh(uint32_t);

    stun::Message send_to_server(stun::Message, bool check_error = true);
    void send_data(QByteArray, HostAddress);
    std::pair<QByteArray, HostAddress> recv_data();

private:
    constexpr static size_t BUFFER_SIZE = 2048;
    std::string _username;
    std::shared_ptr<QUdpSocket> _socket;
    HostAddress _server_addr;
    QByteArray _integrity_key;
    QByteArray _nonce;
};

class ServerError : public std::runtime_error {
public:
    ServerError(const std::string&);
    virtual ~ServerError() noexcept = default;
};

};
